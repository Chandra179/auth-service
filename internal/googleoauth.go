package internal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Chandra179/oauth2-service/configs"
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
	Config     *oauth2.Config
	StateStore StateStorer
	TokenStore TokenStorer
	Logger     *log.Logger
	Limiter    *rate.Limiter
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

func NewGoogleOauth(cfg *configs.Config, stateStore StateStorer, tokenStore TokenStorer, logger *log.Logger) *GoogleOauth {
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.GoogleOauth.ClientID,
		ClientSecret: cfg.GoogleOauth.ClientSecret,
		RedirectURL:  cfg.GoogleOauth.RedirectURL,
		Scopes:       cfg.GoogleOauth.Scopes,
		Endpoint:     cfg.GoogleOauth.Endpoint,
	}

	return &GoogleOauth{
		Config:     oauth2Config,
		StateStore: stateStore,
		TokenStore: tokenStore,
		Logger:     logger,
		Limiter:    rate.NewLimiter(rate.Every(time.Second), 10), // 10 requests per second
	}
}

func generateSecureToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *GoogleOauth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !g.Limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state := generateSecureToken()
	verifier := generateSecureToken()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	g.StateStore.Set(state, verifier)

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

func (g *GoogleOauth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if !g.Limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	state := r.URL.Query().Get("state")
	oauthState, exists := g.StateStore.Get(state)
	if !exists {
		g.Logger.Printf("Invalid state received: %s", state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	g.StateStore.Delete(state)

	code := r.URL.Query().Get("code")
	token, err := g.Config.Exchange(ctx, code, oauth2.VerifierOption(oauthState.Verifier))
	if err != nil {
		g.Logger.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	g.TokenStore.SetToken(token)
	g.Logger.Printf("Token successfully exchanged and stored")
	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (g *GoogleOauth) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if !g.Limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	token := g.TokenStore.GetToken()
	if token == nil {
		g.Logger.Print("No token found")
		http.Error(w, "No token found", http.StatusBadRequest)
		return
	}

	if token.Expiry.Before(time.Now()) {
		ts := g.Config.TokenSource(ctx, token)
		newToken, err := ts.Token()
		if err != nil {
			g.Logger.Printf("Failed to refresh token: %v", err)
			http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
			return
		}
		g.TokenStore.SetToken(newToken)
		g.Logger.Print("Token refreshed successfully")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token refreshed successfully"))
	} else {
		g.Logger.Print("Token is still valid")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token is still valid"))
	}
}

func (g *GoogleOauth) SetupRoutes() {
	http.HandleFunc("/login", g.LoginHandler)
	http.HandleFunc("/callback", g.CallbackHandler)
	http.HandleFunc("/refresh", g.RefreshHandler)
}

func (g *GoogleOauth) StartCleanupRoutine(ctx context.Context, interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				g.StateStore.Cleanup(maxAge)
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (g *GoogleOauth) StartBackgroundRefresh(ctx context.Context, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				token := g.TokenStore.GetToken()
				if token != nil && token.Expiry.Add(-time.Minute).Before(time.Now()) {
					ts := g.Config.TokenSource(ctx, token)
					newToken, err := ts.Token()
					if err != nil {
						g.Logger.Printf("Background refresh failed: %v", err)
					} else {
						g.TokenStore.SetToken(newToken)
						g.Logger.Print("Token refreshed in background")
					}
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
