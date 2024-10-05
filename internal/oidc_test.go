package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chandra179/auth-service/tools/mock/pkg/encryptor"
	"github.com/Chandra179/auth-service/tools/mock/pkg/random"
	"github.com/Chandra179/auth-service/tools/mock/pkg/redis"
	"github.com/Chandra179/auth-service/tools/mock/pkg/serialization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestNewOIDC(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
	}
	redisClient := &redis.MockRedisClient{}
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}
	ctx := context.Background()

	oidcConfig, _ := NewOIDCConfig(ctx, cfg, "issuer", rand, aes, ser, redisClient)

	assert.NotNil(t, oidcConfig)
	assert.Equal(t, cfg.ClientID, oidcConfig.Oauth2Cfg.ClientID)
	assert.Equal(t, cfg.ClientSecret, oidcConfig.Oauth2Cfg.ClientSecret)
	assert.Equal(t, cfg.RedirectURL, oidcConfig.Oauth2Cfg.RedirectURL)
	assert.Equal(t, cfg.Scopes, oidcConfig.Oauth2Cfg.Scopes)
	assert.Equal(t, cfg.Endpoint, oidcConfig.Oauth2Cfg.Endpoint)
}

func TestLogin(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
	}
	redisClient := &redis.MockRedisClient{}
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}
	ctx := context.Background()

	oidcConfig, _ := NewOIDCConfig(ctx, cfg, "issuer", rand, aes, ser, redisClient)

	rand.On("GenerateRandomString").Return("test-state", nil).Once()
	rand.On("GenerateRandomString").Return("test-verifier", nil).Once()
	redisClient.On("Set", "test-state", "test-verifier", 5*time.Minute).Return(nil)

	req, err := http.NewRequest("GET", "/login", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(oidcConfig.Login)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://example.com/auth")

	rand.AssertExpectations(t)
	redisClient.AssertExpectations(t)
}

func TestLoginCallback(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
	}
	redisClient := &redis.MockRedisClient{}
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}
	ctx := context.Background()

	oidcConfig, _ := NewOIDCConfig(ctx, cfg, "issuer", rand, aes, ser, redisClient)

	// Mock Redis expectations
	redisClient.On("Get", "test-state").Return("test-verifier", nil)
	redisClient.On("Delete", "test-state").Return(nil)

	// Define expected token
	expectedToken := oauth2.Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
		ExpiresIn:    3600,
	}

	ser.On("Marshal", mock.AnythingOfType("Token")).Return([]byte("any-serialized-data"), nil)
	aes.On("Encrypt", mock.Anything).Return("encrypted-token", nil)

	// Mock OAuth server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-verifier", r.FormValue("code_verifier"))
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(expectedToken)
		if err != nil {
			return
		}
	}))
	defer ts.Close()

	oidcConfig.Oauth2Cfg.Endpoint.TokenURL = ts.URL

	// Test the callback
	req, err := http.NewRequest("GET", "/callback?state=test-state&code=test-code", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(oidcConfig.LoginCallback)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/success", rr.Header().Get("Location"))
	assert.Equal(t, "access_token", rr.Result().Cookies()[0].Name)
	assert.Equal(t, "encrypted-token", rr.Result().Cookies()[0].Value)

	redisClient.AssertExpectations(t)
	ser.AssertExpectations(t)
	aes.AssertExpectations(t)
}

func TestRefreshToken(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
	}
	redisClient := &redis.MockRedisClient{}
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}
	ctx := context.Background()

	oidcConfig, _ := NewOIDCConfig(ctx, cfg, "issuer", rand, aes, ser, redisClient)

	oldToken := &oauth2.Token{
		AccessToken:  "old-access-token",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh-token",
		Expiry:       time.Now().Add(-time.Hour), // Expired token
	}

	aes.On("Decrypt", "encrypted-old-token").Return([]byte("serialized-old-token"), nil)
	ser.On("Unmarshal", []byte("serialized-old-token"), &oauth2.Token{}).Run(func(args mock.Arguments) {
		token := args.Get(1).(*oauth2.Token)
		*token = *oldToken
	}).Return(nil)

	newTokenJson := &oauth2.Token{
		AccessToken:  "new-access-token",
		TokenType:    "Bearer",
		RefreshToken: "new-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
		ExpiresIn:    3600,
	}

	ser.On("Marshal", mock.AnythingOfType("Token")).Return([]byte("serialized-new-token"), nil)
	aes.On("Encrypt", []byte("serialized-new-token")).Return("encrypted-new-token", nil)

	// Create a test server to mock the token refresh
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(newTokenJson)
		if err != nil {
			return
		}
	}))
	defer ts.Close()

	// Override the token URL for testing
	oidcConfig.Oauth2Cfg.Endpoint.TokenURL = ts.URL

	req, err := http.NewRequest("GET", "/refresh", nil)
	assert.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "encrypted-old-token"})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(oidcConfig.RefreshToken)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "access_token", rr.Result().Cookies()[0].Name)
	assert.Equal(t, "encrypted-new-token", rr.Result().Cookies()[0].Value)

	aes.AssertExpectations(t)
	ser.AssertExpectations(t)
}
