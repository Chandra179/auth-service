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

type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockRedisClient) Get(key string) (string, error) {
	args := m.Called(key)
	return args.String(0), args.Error(1)
}

func (m *MockRedisClient) Delete(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

// Mock AesEncryptor
type MockAesEncryptor struct {
	mock.Mock
}

func (m *MockAesEncryptor) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *MockAesEncryptor) Decrypt(encryptedData string) ([]byte, error) {
	args := m.Called(encryptedData)
	return args.Get(0).([]byte), args.Error(1)
}

// Mock SerializationManager
type MockSerializationManager struct {
	mock.Mock
}

func (m *MockSerializationManager) ToBytes(v interface{}) ([]byte, error) {
	args := m.Called(v)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerializationManager) FromBytes(data []byte, v interface{}) error {
	args := m.Called(data, v)
	return args.Error(0)
}

// Mock Random
type MockRandom struct {
	mock.Mock
}

func (m *MockRandom) GenerateRandomString() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
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
	redisClient := &MockRedisClient{}
	logger := log.New(bytes.NewBuffer([]byte{}), "", log.LstdFlags)
	aes := &MockAesEncryptor{}
	ser := &MockSerializationManager{}
	rand := &MockRandom{}

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
	redisClient := &MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &MockAesEncryptor{}
	ser := &MockSerializationManager{}
	rand := &MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	rand.On("GenerateRandomString").Return("test-state", nil).Once()
	rand.On("GenerateRandomString").Return("test-verifier", nil).Once()
	redisClient.On("Set", "test-state", "test-verifier", 5*time.Minute).Return()

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
	cfg := &configs.Config{
		GoogleOauth: oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint:     oauth2.Endpoint{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token"},
		},
	}
	redisClient := &MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &MockAesEncryptor{}
	ser := &MockSerializationManager{}
	rand := &MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	redisClient.On("Get", "test-state").Return("test-verifier", nil)
	redisClient.On("Delete", "test-state").Return()

	tokenJson := Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
		ExpiresIn:    3600,
	}

	ser.On("ToBytes", mock.AnythingOfType("Token")).Return([]byte("serialized-token"), nil)
	aes.On("Encrypt", []byte("serialized-token")).Return("encrypted-token", nil)

	// Create a test server to mock the token exchange
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-verifier", r.FormValue("code_verifier"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenJson)
	}))
	defer ts.Close()

	// Override the token URL for testing
	googleOauth.config.Endpoint.TokenURL = ts.URL

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
	redisClient := &MockRedisClient{}
	var logBuffer bytes.Buffer
	logger := log.New(&logBuffer, "", log.LstdFlags)
	aes := &MockAesEncryptor{}
	ser := &MockSerializationManager{}
	rand := &MockRandom{}

	googleOauth := NewGoogleOauth(cfg, redisClient, logger, aes, ser, rand)

	oldToken := &oauth2.Token{
		AccessToken:  "old-access-token",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh-token",
		Expiry:       time.Now().Add(-time.Hour), // Expired token
	}

	aes.On("Decrypt", "encrypted-old-token").Return([]byte("serialized-old-token"), nil)
	ser.On("FromBytes", []byte("serialized-old-token"), &oauth2.Token{}).Run(func(args mock.Arguments) {
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

	ser.On("ToBytes", mock.AnythingOfType("Token")).Return([]byte("serialized-new-token"), nil)
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
