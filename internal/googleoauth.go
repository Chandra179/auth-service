package internal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/redis"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type OAuthState struct {
	State    string
	Verifier string
	Created  time.Time
}

type StateStore struct {
	m map[string]OAuthState
	sync.RWMutex
}

func NewStateStore() *StateStore {
	return &StateStore{m: make(map[string]OAuthState)}
}

func (s *StateStore) Set(state, verifier string) {
	s.Lock()
	defer s.Unlock()
	s.m[state] = OAuthState{
		State:    state,
		Verifier: verifier,
		Created:  time.Now(),
	}
}

func (s *StateStore) Get(state string) (OAuthState, bool) {
	s.RLock()
	defer s.RUnlock()
	oauthState, exists := s.m[state]
	return oauthState, exists
}

func (s *StateStore) Delete(state string) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, state)
}

func (s *StateStore) Cleanup(maxAge time.Duration) {
	s.Lock()
	defer s.Unlock()
	for state, oauthState := range s.m {
		if time.Since(oauthState.Created) > maxAge {
			delete(s.m, state)
		}
	}
}

type TokenStore struct {
	token *oauth2.Token
	mu    sync.RWMutex
}

func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

func (ts *TokenStore) SetToken(token *oauth2.Token) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.token = token
}

func (ts *TokenStore) GetToken() *oauth2.Token {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.token
}

type GoogleOauth struct {
	Config      *oauth2.Config
	StateStore  StateStorer
	TokenStore  TokenStorer
	Logger      *log.Logger
	Limiter     *rate.Limiter
	RedisClient *redis.RedisClient
}

type StateStorer interface {
	Set(state, verifier string)
	Get(state string) (OAuthState, bool)
	Delete(state string)
	Cleanup(maxAge time.Duration)
}

type TokenStorer interface {
	SetToken(token *oauth2.Token)
	GetToken() *oauth2.Token
}

func NewGoogleOauth(cfg *configs.Config, redisClient *redis.RedisClient, logger *log.Logger) *GoogleOauth {
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.GoogleOauth.ClientID,
		ClientSecret: cfg.GoogleOauth.ClientSecret,
		RedirectURL:  cfg.GoogleOauth.RedirectURL,
		Scopes:       cfg.GoogleOauth.Scopes,
		Endpoint:     cfg.GoogleOauth.Endpoint,
	}

	return &GoogleOauth{
		Config:      oauth2Config,
		RedisClient: redisClient,
		Logger:      logger,
		Limiter:     rate.NewLimiter(rate.Every(time.Second), 10), // 10 requests per second
	}
}

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (g *GoogleOauth) Login(w http.ResponseWriter, r *http.Request) {
	if !g.Limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state, err := generateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}
	verifier, err := generateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	g.RedisClient.Set(state, verifier, 5*time.Minute)
	// g.StateStore.Set(state, verifier)

	authURL := g.Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	g.Logger.Printf("Generated auth URL: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (g *GoogleOauth) LoginCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if !g.Limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state := r.URL.Query().Get("state")
	oauthState, exists := g.RedisClient.Get(state)
	// oauthState, exists := g.StateStore.Get(state)
	if exists != nil {
		g.Logger.Printf("Invalid state received: %s", state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	g.RedisClient.Delete(state)
	// g.StateStore.Delete(state)

	code := r.URL.Query().Get("code")
	token, err := g.Config.Exchange(ctx, code, oauth2.VerifierOption(oauthState))
	if err != nil {
		g.Logger.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Set the HTTP-only and secure cookies for access and refresh tokens
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token, // consist of (access_token, refresh, expired, etc..)
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                    // Ensure this is set to true when using HTTPS
		SameSite: http.SameSiteStrictMode, // Adjust as per your requirements
	})

	// g.TokenStore.SetToken(token)
	g.Logger.Printf("Token successfully exchanged and stored")
	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (g *GoogleOauth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// token := g.TokenStore.GetToken()
	token, err := g.Config.TokenSource(ctx, token).Token()
	if err != nil {
		g.Logger.Printf("Refresh failed: %v", err)
	} else {
		g.TokenStore.SetToken(token)
	}
}
