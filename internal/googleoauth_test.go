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
	"github.com/Chandra179/auth-service/tools/mock/pkg/encryptor"
	"github.com/Chandra179/auth-service/tools/mock/pkg/random"
	"github.com/Chandra179/auth-service/tools/mock/pkg/redis"
	"github.com/Chandra179/auth-service/tools/mock/pkg/serialization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

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
	redisClient := &redis.MockRedisClient{}
	logger := log.New(bytes.NewBuffer([]byte{}), "", log.LstdFlags)
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	assert.NotNil(t, googleOauth)
	assert.Equal(t, cfg.GoogleOauth.ClientID, googleOauth.config.ClientID)
	assert.Equal(t, cfg.GoogleOauth.ClientSecret, googleOauth.config.ClientSecret)
	assert.Equal(t, cfg.GoogleOauth.RedirectURL, googleOauth.config.RedirectURL)
	assert.Equal(t, cfg.GoogleOauth.Scopes, googleOauth.config.Scopes)
	assert.Equal(t, cfg.GoogleOauth.Endpoint, googleOauth.config.Endpoint)
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
	redisClient := &redis.MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	rand.On("GenerateRandomString").Return("test-state", nil).Once()
	rand.On("GenerateRandomString").Return("test-verifier", nil).Once()
	redisClient.On("Set", "test-state", "test-verifier", 5*time.Minute).Return(nil)

	req, err := http.NewRequest("GET", "/login", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.Login)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "http://example.com/auth")

	rand.AssertExpectations(t)
	redisClient.AssertExpectations(t)
	assert.Contains(t, logBuffer.String(), "Generated auth URL:")
}

func TestLoginCallback(t *testing.T) {
	// Setup
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	redisClient := &redis.MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	// Mock Redis expectations
	redisClient.On("Get", "test-state").Return("test-verifier", nil)
	redisClient.On("Delete", "test-state").Return(nil)

	// Define expected token
	expectedToken := Token{
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
		json.NewEncoder(w).Encode(expectedToken)
	}))
	defer ts.Close()

	googleOauth.config.Endpoint.TokenURL = ts.URL

	// Test the callback
	req, err := http.NewRequest("GET", "/callback?state=test-state&code=test-code", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.LoginCallback)
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
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	redisClient := &redis.MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &encryptor.MockAesEncryptor{}
	ser := &serialization.MockSerialization{}
	rand := &random.MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

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

	newTokenJson := Token{
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
		json.NewEncoder(w).Encode(newTokenJson)
	}))
	defer ts.Close()

	// Override the token URL for testing
	googleOauth.config.Endpoint.TokenURL = ts.URL

	req, err := http.NewRequest("GET", "/refresh", nil)
	assert.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "encrypted-old-token"})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(googleOauth.RefreshToken)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "access_token", rr.Result().Cookies()[0].Name)
	assert.Equal(t, "encrypted-new-token", rr.Result().Cookies()[0].Value)

	aes.AssertExpectations(t)
	ser.AssertExpectations(t)
}
