package internal

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryptor"
	oauth2proxy "github.com/Chandra179/auth-service/pkg/oauth2"
	"github.com/Chandra179/auth-service/pkg/oidc"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serialization"
	"golang.org/x/oauth2"
)

type AuthConfig struct {
	oidcProxy     oidc.OIDCProxy
	oauth2Proxy   oauth2proxy.Oauth2Proxy
	cfg           *configs.Config
	random        random.RandomOperations
	aes           encryptor.AesOperations
	serialization serialization.SerializationOperations
	redisOpr      redis.RedisOperations
}

type UserClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type Oauth2State struct {
	Verifier string
	Provider string
}

func NewAuthentication(ctx context.Context, cfg *configs.Config, rand random.RandomOperations, aes encryptor.AesOperations,
	ser serialization.SerializationOperations, redisOpr redis.RedisOperations) (*AuthConfig, error) {
	config := &AuthConfig{
		random:        rand,
		aes:           aes,
		serialization: ser,
		redisOpr:      redisOpr,
		cfg:           cfg,
	}

	return config, nil
}

func (o *AuthConfig) Login(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	provider := path[len("/login/"):] // Gets everything after "/login/"
	if provider == "" {
		http.Error(w, "Provider is required", http.StatusBadRequest)
		return
	}

	oauth2Cfg, err := o.cfg.GetProvider(provider, o.cfg)
	if err != nil {
		http.Error(w, "Provider not found", http.StatusNotFound)
		return
	}
	o.oauth2Proxy = oauth2proxy.NewOauth2(&oauth2Cfg.Oauth2Cfg)

	state, err := o.random.GenerateRandomString(32)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	verifier, err := o.random.GenerateRandomString(32)
	if err != nil {
		http.Error(w, "Failed to generate verifier", http.StatusInternalServerError)
		return
	}

	// temporary store state: {verifier, provider} in redis, state will be used for LoginCallback state validation
	// assuming we will receive the callback within 5 minute after login
	byteState, err := o.serialization.Marshal(&Oauth2State{Verifier: verifier, Provider: provider})
	if err != nil {
		http.Error(w, "Failed to serialize state"+err.Error(), http.StatusInternalServerError)
	}
	err = o.redisOpr.Set(state, byteState, 5*time.Minute)
	if err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	challenge := o.oauth2Proxy.S256ChallengeFromVerifier(verifier)
	authURL := o.oauth2Proxy.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (o *AuthConfig) LoginCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	reqState := r.URL.Query().Get("state")
	state, exists := o.redisOpr.Get(reqState)
	if exists != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	curState := &Oauth2State{}
	err := o.serialization.Unmarshal(state, curState)
	if err != nil {
		http.Error(w, "Error deserealize token", http.StatusInternalServerError)
		return
	}

	oauth2Cfg, _ := o.cfg.GetProvider(curState.Provider, o.cfg)
	o.oauth2Proxy = oauth2proxy.NewOauth2(&oauth2Cfg.Oauth2Cfg)

	oidc, err := oidc.NewOIDCProxy(r.Context(), oauth2Cfg.Oauth2Issuer)
	if err != nil {
		fmt.Println("oidc initialize err", err)
	}
	o.oidcProxy = oidc

	// Exchange code for token
	oauth2Token, err := o.oauth2Proxy.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(curState.Verifier))
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Extract the ID Token
	rawIDToken, ok := o.oauth2Proxy.Extra("id_token", oauth2Token).(string)
	if !ok {
		http.Error(w, "No ID token found", http.StatusInternalServerError)
		return
	}

	// Verify the ID Token
	verifiedToken := o.oidcProxy.Verifier(oauth2Cfg.Oauth2Cfg.ClientID)
	idToken, err := o.oidcProxy.Verify(r.Context(), verifiedToken, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	// Extract custom claims
	var claims UserClaims
	if err := o.oidcProxy.Claims(idToken, &claims); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Serialize token
	byteCode, err := o.serialization.Marshal(oauth2Token)
	if err != nil {
		http.Error(w, "Failed to serializa token", http.StatusInternalServerError)
	}

	// Encrypt token
	encryptedCode, err := o.aes.Encrypt(byteCode)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
	}

	// Set the HTTP-only and secure cookies for access and refresh tokens
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    encryptedCode, // consist of (session_token, refresh, expired, etc..)
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                    // Ensure this is set to true when using HTTPS
		SameSite: http.SameSiteLaxMode, // Adjust as per your requirements
	})

	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (o *AuthConfig) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Cookie not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Error retrieving cookie", http.StatusInternalServerError)
		return
	}

	tokenByte, err := o.aes.Decrypt(cookie.Value)
	if err != nil {
		http.Error(w, "Error decrypting token", http.StatusInternalServerError)
		return
	}

	token := &oauth2.Token{}
	err = o.serialization.Unmarshal(tokenByte, token)
	if err != nil {
		http.Error(w, "Error deserealize token", http.StatusInternalServerError)
		return
	}

	newToken, err := o.oauth2Proxy.TokenSource(ctx, token).Token()
	if err != nil {
		http.Error(w, "Refresh token failed", http.StatusInternalServerError)
		return
	}

	byteCode, err := o.serialization.Marshal(newToken)
	if err != nil {
		http.Error(w, "Failed to serializa token", http.StatusInternalServerError)
	}

	encryptedCode, err := o.aes.Encrypt(byteCode)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    encryptedCode, // consist of (access_token, refresh, expired, etc..)
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                    // Ensure this is set to true when using HTTPS
		SameSite: http.SameSiteLaxMode, // Adjust as per your requirements
	})
}

// func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
// 	// Get the access token from the Authorization header
// 	authHeader := r.Header.Get("Authorization")
// 	if authHeader == "" {
// 		http.Error(w, "No authorization header", http.StatusUnauthorized)
// 		return
// 	}

// 	// Use the provider's UserInfo endpoint
// 	userInfo, err := s.oidcConfig.Provider.UserInfo(r.Context(), oauth2.StaticTokenSource(
// 		&oauth2.Token{AccessToken: authHeader[7:]}, // Remove "Bearer " prefix
// 	))
// 	if err != nil {
// 		http.Error(w, "Failed to get userinfo", http.StatusInternalServerError)
// 		return
// 	}

// 	var claims UserClaims
// 	if err := userInfo.Claims(&claims); err != nil {
// 		http.Error(w, "Failed to extract userinfo claims", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(claims)
// }
