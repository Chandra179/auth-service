package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Chandra179/auth-service/pkg/encryptor"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serialization"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Provider  *oidc.Provider
	Verifier  *oidc.IDTokenVerifier
	Oauth2Cfg *oauth2.Config
	Issuer    string
	rand      random.RandomOperations
	aes       encryptor.AesOperations
	ser       serialization.SerializationOperations
	redisOpr  redis.RedisOperations
}

type UserClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type State struct {
	State    string
	Verifier string
}

func NewOIDCConfig(ctx context.Context, cfg *oauth2.Config, issuer string, rand random.RandomOperations,
	aes encryptor.AesOperations, ser serialization.SerializationOperations, redisOpr redis.RedisOperations) (*OIDCConfig, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	config := &OIDCConfig{
		Provider: provider,
		Verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		}),
		Oauth2Cfg: cfg,
		rand:      rand,
		aes:       aes,
		ser:       ser,
		redisOpr:  redisOpr,
	}

	return config, nil
}

func (o *OIDCConfig) Login(w http.ResponseWriter, r *http.Request) {
	state, err := o.rand.GenerateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}
	verifier, err := o.rand.GenerateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}

	// temporary store state in redis, state will be used for LoginCallback state validation
	// assuming will receive the callback within 5 minute after login
	err = o.redisOpr.Set(state, verifier, 5*time.Minute)
	if err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	// Redirect to the identity provider
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	authURL := o.Oauth2Cfg.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (o *OIDCConfig) LoginCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	state := r.URL.Query().Get("state")
	verifier, exists := o.redisOpr.Get(state)
	if exists != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, err := o.Oauth2Cfg.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		http.Error(w, "Failed to exchange token"+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract the ID Token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token found", http.StatusInternalServerError)
		return
	}

	// Verify the ID Token
	idToken, err := o.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	// Extract custom claims
	var claims UserClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Return user info as JSON (in practice, you'd typically create a session here)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (o *OIDCConfig) RefreshToken(w http.ResponseWriter, r *http.Request) {

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
