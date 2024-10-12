package internal

import (
	"context"
	"net/http"
	"time"

	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryption"
	oauth2Client "github.com/Chandra179/auth-service/pkg/oauth2"
	oidcClient "github.com/Chandra179/auth-service/pkg/oidc"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serializer"
	"golang.org/x/oauth2"
)

type Oauth2Service struct {
	oidcClient   oidcClient.OIDCClient
	oauth2Client oauth2Client.Oauth2Client
	config       *configs.AppConfig
	randomGen    random.RandomGenerator
	encryptor    encryption.AESEncryptor
	serializer   serializer.JSONSerializer
	cacheStore   redis.RedisStore
}

type UserProfile struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type AuthState struct {
	Verifier string
	Provider string
}

func NewOauth2Service(ctx context.Context, cfg *configs.AppConfig, randGen random.RandomGenerator,
	encryptor encryption.AESEncryptor, ser serializer.JSONSerializer,
	cacheStore redis.RedisStore) (*Oauth2Service, error) {
	return &Oauth2Service{
		randomGen:  randGen,
		encryptor:  encryptor,
		serializer: ser,
		cacheStore: cacheStore,
		config:     cfg,
	}, nil
}

func (s *Oauth2Service) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	provider := path[len("/login/"):]
	if provider == "" {
		http.Error(w, "Provider is required", http.StatusBadRequest)
		return
	}

	oauth2Cfg, err := s.config.GetProviderConfig(provider, s.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.oauth2Client = oauth2Client.NewOauth2Client(&oauth2Cfg.Oauth2Config)

	state, err := s.randomGen.String(32)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	verifier, err := s.randomGen.String(32)
	if err != nil {
		http.Error(w, "Failed to generate verifier", http.StatusInternalServerError)
		return
	}

	authState := &AuthState{Verifier: verifier, Provider: provider}
	encodedState, err := s.serializer.Encode(authState)
	if err != nil {
		http.Error(w, "Failed to serialize state", http.StatusInternalServerError)
		return
	}

	if err := s.cacheStore.Set(state, encodedState, 5*time.Minute); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	challenge := s.oauth2Client.S256ChallengeFromVerifier(verifier)
	authURL := s.oauth2Client.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (s *Oauth2Service) HandleLoginCallback(w http.ResponseWriter, r *http.Request) {
	reqState := r.URL.Query().Get("state")
	encodedState, err := s.cacheStore.Get(reqState)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	authState := &AuthState{}
	if err := s.serializer.Decode(encodedState, authState); err != nil {
		http.Error(w, "Error deserializing state", http.StatusInternalServerError)
		return
	}

	oauth2Cfg, err := s.config.GetProviderConfig(authState.Provider, s.config)
	if err != nil {
		http.Error(w, "Invalid provider", http.StatusBadRequest)
		return
	}
	s.oauth2Client = oauth2Client.NewOauth2Client(&oauth2Cfg.Oauth2Config)

	oidc, err := oidcClient.NewOIDCClient(r.Context(), oauth2Cfg.Oauth2Issuer)
	if err != nil {
		http.Error(w, "Failed to initialize OIDC client", http.StatusInternalServerError)
		return
	}
	s.oidcClient = oidc

	oauth2Token, err := s.oauth2Client.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(authState.Verifier))
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := s.oauth2Client.Extra("id_token", oauth2Token).(string)
	if !ok {
		http.Error(w, "No ID token found", http.StatusInternalServerError)
		return
	}

	verifiedToken := s.oidcClient.Verifier(oauth2Cfg.Oauth2Config.ClientID)
	idToken, err := s.oidcClient.Verify(r.Context(), verifiedToken, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	if err := idToken.VerifyAccessToken(oauth2Token.AccessToken); err != nil {
		http.Error(w, "Access token not verified: "+err.Error(), http.StatusBadRequest)
		return
	}

	var userProfile UserProfile
	if err := s.oidcClient.Claims(idToken, &userProfile); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	if !userProfile.EmailVerified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		return
	}

	encodedToken, err := s.serializer.Encode(oauth2Token)
	if err != nil {
		http.Error(w, "Failed to serialize token", http.StatusInternalServerError)
		return
	}

	encryptedToken, err := s.encryptor.Encrypt(encodedToken)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    encryptedToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (s *Oauth2Service) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Cookie not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error retrieving cookie", http.StatusInternalServerError)
		}
		return
	}

	decryptedToken, err := s.encryptor.Decrypt(cookie.Value)
	if err != nil {
		http.Error(w, "Error decrypting token", http.StatusInternalServerError)
		return
	}

	var token oauth2.Token
	if err := s.serializer.Decode(decryptedToken, &token); err != nil {
		http.Error(w, "Error deserializing token", http.StatusInternalServerError)
		return
	}

	newToken := s.oauth2Client.TokenSource(ctx, &token)
	encodedToken, err := s.serializer.Encode(newToken)
	if err != nil {
		http.Error(w, "Failed to serialize token", http.StatusInternalServerError)
		return
	}

	encryptedToken, err := s.encryptor.Encrypt(encodedToken)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    encryptedToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
