package internal

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chandra179/auth-service/configs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// Mock StateStorer
type MockStateStorer struct {
	mock.Mock
}

func (m *MockStateStorer) Set(state, verifier string) {
	m.Called(state, verifier)
}

func (m *MockStateStorer) Get(state string) (OAuthState, bool) {
	args := m.Called(state)
	return args.Get(0).(OAuthState), args.Bool(1)
}

func (m *MockStateStorer) Delete(state string) {
	m.Called(state)
}

func (m *MockStateStorer) Cleanup(maxAge time.Duration) {
	m.Called(maxAge)
}

// Mock TokenStorer
type MockTokenStorer struct {
	mock.Mock
}

func (m *MockTokenStorer) SetToken(token *oauth2.Token) {
	m.Called(token)
}

func (m *MockTokenStorer) GetToken() *oauth2.Token {
	args := m.Called()
	return args.Get(0).(*oauth2.Token)
}

func TestNewGoogleOauth(t *testing.T) {
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	stateStore := &MockStateStorer{}
	tokenStore := &MockTokenStorer{}
	logger := log.New(bytes.NewBuffer([]byte{}), "", log.LstdFlags)

	googleOauth := NewGoogleOauth(cfg, stateStore, tokenStore, logger)

	assert.NotNil(t, googleOauth)
	assert.Equal(t, cfg.GoogleOauth.ClientID, googleOauth.Config.ClientID)
	assert.Equal(t, cfg.GoogleOauth.ClientSecret, googleOauth.Config.ClientSecret)
	assert.Equal(t, cfg.GoogleOauth.RedirectURL, googleOauth.Config.RedirectURL)
	assert.Equal(t, cfg.GoogleOauth.Scopes, googleOauth.Config.Scopes)
	assert.Equal(t, cfg.GoogleOauth.Endpoint, googleOauth.Config.Endpoint)
}

func TestLogin(t *testing.T) {
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	stateStore := &MockStateStorer{}
	tokenStore := &MockTokenStorer{}

	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)

	googleOauth := NewGoogleOauth(cfg, stateStore, tokenStore, logger)

	stateStore.On("Set", mock.Anything, mock.Anything).Return()

	req, err := http.NewRequest("GET", "/login", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.Login)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://example.com/auth")

	stateStore.AssertExpectations(t)
	assert.Contains(t, logBuffer.String(), "Generated auth URL:")
}

func TestLoginCallback(t *testing.T) {
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	stateStore := &MockStateStorer{}
	tokenStore := &MockTokenStorer{}

	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)

	googleOauth := NewGoogleOauth(cfg, stateStore, tokenStore, logger)

	// Mock the state store
	stateStore.On("Get", "test-state").Return(OAuthState{
		State:    "test-state",
		Verifier: "test-verifier",
		Created:  time.Now(),
	}, true)
	stateStore.On("Delete", "test-state").Return()

	// Mock the token store
	tokenStore.On("SetToken", mock.AnythingOfType("*oauth2.Token")).Return()

	// Create a test server to mock the token exchange
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-verifier", r.FormValue("code_verifier"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"refresh_token": "test-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	// Override the token URL for testing
	googleOauth.Config.Endpoint.TokenURL = ts.URL

	req, err := http.NewRequest("GET", "/callback?state=test-state&code=test-code", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.LoginCallback)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/success?access_token=test-access-token")

	stateStore.AssertExpectations(t)
	tokenStore.AssertExpectations(t)
	assert.Contains(t, logBuffer.String(), "Token successfully exchanged and stored")
}

func TestRefreshToken(t *testing.T) {
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	stateStore := &MockStateStorer{}
	tokenStore := &MockTokenStorer{}

	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)

	googleOauth := NewGoogleOauth(cfg, stateStore, tokenStore, logger)

	// Mock the token store
	oldToken := &oauth2.Token{
		AccessToken:  "old-access-token",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh-token",
		Expiry:       time.Now().Add(-time.Hour), // Expired token
	}
	tokenStore.On("GetToken").Return(oldToken)
	tokenStore.On("SetToken", mock.AnythingOfType("*oauth2.Token")).Return()

	// Create a test server to mock the token refresh
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access-token",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	// Override the token URL for testing
	googleOauth.Config.Endpoint.TokenURL = ts.URL

	req, err := http.NewRequest("GET", "/refresh", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.RefreshToken)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	tokenStore.AssertExpectations(t)
	assert.NotContains(t, logBuffer.String(), "Refresh failed")
}
