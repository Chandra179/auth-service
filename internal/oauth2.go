/*
Package internal provides an implementation of an OAuth2 service for user authentication.
It supports initiating login with OAuth2 providers, handling login callbacks, and refreshing access tokens.
This package is designed to work with various OAuth2 and OIDC (OpenID Connect) providers.

Components:
- Oauth2Service: The main structure that handles OAuth2 operations.
- UserProfile: Structure representing user profile information.
- AuthState: Structure used to maintain the state during the OAuth2 flow.

Usage:
To use this package, initialize the Oauth2Service with the necessary dependencies and call
the appropriate methods to initiate login, handle callbacks, and refresh tokens.
*/

// Package internal provides an implementation of an OAuth2 service for user authentication.
package internal

import (
	"context"
	"fmt"
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

// Oauth2Service is the main structure that handles OAuth2 operations.
type Oauth2Service struct {
	oidcClient   oidcClient.OIDCClient
	oauth2Client oauth2Client.Oauth2Client
	config       configs.AppConfigInterface
	randomGen    random.RandomGenerator
	encryptor    encryption.AESEncryptor
	serializer   serializer.JSONSerializer
	cacheStore   redis.RedisStore
}

// UserProfile represents the user profile information retrieved from the OAuth2 provider.
type UserProfile struct {
	Email         string `json:"email"`          // User's email address
	EmailVerified bool   `json:"email_verified"` // Flag indicating if the user's email is verified
	Name          string `json:"name"`           // User's name
}

// AuthState holds the verifier and provider information during the OAuth2 flow.
type AuthState struct {
	Verifier string // The code verifier for PKCE
	Provider string // The name of the OAuth2 provider
}

// NewOauth2Service creates a new Oauth2Service instance with the provided dependencies.
// Parameters:
//   - ctx: The context for managing request lifecycle.
//   - cfg: Application configuration interface.
//   - randGen: Random generator for generating unique state and verifier.
//   - encryptor: Encryptor for securing tokens.
//   - ser: Serializer for encoding and decoding data.
//   - cacheStore: Cache store for managing state.
//   - oidcClient: OIDC client for handling OpenID Connect functionalities.
//   - oauth2Client: OAuth2 client for handling OAuth2 operations.
//
// Returns:
//   - A pointer to the newly created Oauth2Service instance.
//   - An error if the initialization fails.
func NewOauth2Service(ctx context.Context, cfg configs.AppConfigInterface, randGen random.RandomGenerator,
	encryptor encryption.AESEncryptor, ser serializer.JSONSerializer, cacheStore redis.RedisStore,
	oidcClient oidcClient.OIDCClient, oauth2Client oauth2Client.Oauth2Client) (*Oauth2Service, error) {
	return &Oauth2Service{
		randomGen:    randGen,
		encryptor:    encryptor,
		serializer:   ser,
		cacheStore:   cacheStore,
		config:       cfg,
		oidcClient:   oidcClient,
		oauth2Client: oauth2Client,
	}, nil
}

// InitiateLogin starts the OAuth2 login process by redirecting the user to the provider's authorization URL.
// Parameters:
//   - w: The http.ResponseWriter for sending responses to the client.
//   - r: The http.Request containing the login request.
//
// Returns:
//   - An error response if any step in the process fails.
func (s *Oauth2Service) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	provider := path[len("/login/"):]
	if provider == "" {
		http.Error(w, "Provider is required", http.StatusBadRequest)
		return
	}

	// Handle OAuth2 provider configuration
	oauth2Cfg, err := s.config.GetOauth2ProviderConfig(provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.oauth2Client.SetConfig(&oauth2Cfg.Oauth2Config)

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

// HandleLoginCallback handles the OAuth2 provider's callback after the user has logged in.
// It validates the state, exchanges the authorization code for tokens, and verifies the ID token.
// Parameters:
//   - w: The http.ResponseWriter for sending responses to the client.
//   - r: The http.Request containing the callback request.
//
// Returns:
//   - An error response if any step in the process fails.
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

	oauth2Cfg, err := s.config.GetOauth2ProviderConfig(authState.Provider)
	if err != nil {
		fmt.Println("err" + err.Error())
		http.Error(w, "Invalid provider", http.StatusBadRequest)
		return
	}
	s.oauth2Client.SetConfig(&oauth2Cfg.Oauth2Config)

	// Set OIDC configuration
	err = s.oidcClient.NewProvider(r.Context(), oauth2Cfg.Oauth2Issuer)
	if err != nil {
		http.Error(w, "Failed to initialize Provider", http.StatusInternalServerError)
		return
	}

	oauth2Token, err := s.oauth2Client.Exchange(context.Background(), r.URL.Query().Get("code"), authState.Verifier)
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

	if err := s.oidcClient.VerifyAccessToken(idToken, oauth2Token.AccessToken); err != nil {
		http.Error(w, "Access token not verified: "+err.Error(), http.StatusBadRequest)
		return
	}

	var userProfile UserProfile
	if err := s.oidcClient.Claims(idToken, &userProfile); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	if !s.oidcClient.IsEmailVerified(userProfile.EmailVerified) {
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

// RefreshToken refreshes the OAuth2 token by exchanging the current session token for a new one.
// Parameters:
//   - w: The http.ResponseWriter for sending responses to the client.
//   - r: The http.Request containing the refresh request.
//
// Returns:
//   - An error response if the refresh operation fails.
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
