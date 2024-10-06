package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chandra179/auth-service/tools/mock/pkg/encryptor"
	oauth2mock "github.com/Chandra179/auth-service/tools/mock/pkg/oauth2"
	oidcmock "github.com/Chandra179/auth-service/tools/mock/pkg/oidc"

	"github.com/Chandra179/auth-service/tools/mock/pkg/random"
	"github.com/Chandra179/auth-service/tools/mock/pkg/redis"
	"github.com/Chandra179/auth-service/tools/mock/pkg/serialization"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestLogin_WhenAllSystemsOperational_ShouldRedirectToAuthProvider(t *testing.T) {
	// Setup
	mockRand := &random.MockRandom{}
	mockRedis := &redis.MockRedisClient{}
	mockOauth2Proxy := &oauth2mock.MockOauth2Proxy{}

	config := &AuthConfig{
		random:      mockRand,
		redisOpr:    mockRedis,
		oauth2Proxy: mockOauth2Proxy,
		oauth2Cfg:   &oauth2.Config{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)

	mockRand.On("GenerateRandomString", int64(32)).Return("abcd", nil).Times(2)
	mockRedis.On("Set", "abcd", "abcd", 5*time.Minute).Return(nil).Once()
	mockOauth2Proxy.On("S256ChallengeFromVerifier", "abcd").Return("challenge123").Once()
	mockOauth2Proxy.On("AuthCodeURL", "abcd", mock.Anything).Return("https://example.com/auth").Once()

	config.Login(w, r)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "https://example.com/auth")

	mockRand.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
	mockOauth2Proxy.AssertExpectations(t)
}

func TestLoginCallback_WhenValidStateAndCode_ShouldSetAccessTokenCookie(t *testing.T) {
	// Setup
	mockRand := &random.MockRandom{}
	mockRedis := &redis.MockRedisClient{}
	mockOauth2Proxy := &oauth2mock.MockOauth2Proxy{}
	mockOIDCProxy := &oidcmock.MockOIDCProxy{}
	mockSer := &serialization.MockSerialization{}
	mockAes := &encryptor.MockAesEncryptor{}

	config := &AuthConfig{
		redisOpr:      mockRedis,
		oauth2Proxy:   mockOauth2Proxy,
		oidcProxy:     mockOIDCProxy,
		serialization: mockSer,
		aes:           mockAes,
		random:        mockRand,
		oauth2Cfg:     &oauth2.Config{ClientID: "test-client"},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=state123&code=code123", nil)

	token := &oauth2.Token{AccessToken: "access123"}
	verifier := "verifier123"
	rawIDToken := "raw-id-token"
	verifierObj := &oidc.IDTokenVerifier{}
	verifiedToken := &oidc.IDToken{}

	mockRedis.On("Get", "state123").Return(verifier, nil).Once()
	mockOauth2Proxy.On("Exchange", r.Context(), "code123", mock.Anything).Return(token, nil).Once()
	mockOauth2Proxy.On("Extra", "id_token", token).Return(rawIDToken).Once()
	mockOIDCProxy.On("Verifier", "test-client").Return(verifierObj).Once()
	mockOIDCProxy.On("Verify", r.Context(), verifierObj, rawIDToken).Return(verifiedToken, nil).Once()
	mockOIDCProxy.On("Claims", verifiedToken, mock.AnythingOfType("*internal.UserClaims")).Return(nil).Once()

	tokenBytes := []byte("serialized-token")
	mockSer.On("Marshal", token).Return(tokenBytes, nil).Once()
	mockAes.On("Encrypt", tokenBytes).Return("encrypted-token", nil).Once()

	config.LoginCallback(w, r)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/success", w.Header().Get("Location"))

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "access_token", cookie.Name)
	assert.Equal(t, "encrypted-token", cookie.Value)

	mockRedis.AssertExpectations(t)
	mockOauth2Proxy.AssertExpectations(t)
	mockOIDCProxy.AssertExpectations(t)
	mockSer.AssertExpectations(t)
	mockAes.AssertExpectations(t)
}

func TestRefreshToken_WhenValidAccessToken_ShouldRefreshAndUpdateCookie(t *testing.T) {
	// Setup
	mockOauth2Proxy := &oauth2mock.MockOauth2Proxy{}
	mockSer := &serialization.MockSerialization{}
	mockAes := &encryptor.MockAesEncryptor{}

	config := &AuthConfig{
		aes:           mockAes,
		serialization: mockSer,
		oauth2Proxy:   mockOauth2Proxy,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "encrypted-token"})

	decryptedToken := []byte("decrypted-token")
	oldToken := &oauth2.Token{AccessToken: "old-token"}
	newToken := &oauth2.Token{AccessToken: "new-token"}
	tokenSource := oauth2.StaticTokenSource(newToken)

	mockAes.On("Decrypt", "encrypted-token").Return(decryptedToken, nil).Once()
	mockSer.On("Unmarshal", decryptedToken, mock.AnythingOfType("*oauth2.Token")).Run(func(args mock.Arguments) {
		token := args.Get(1).(*oauth2.Token)
		*token = *oldToken
	}).Return(nil).Once()
	mockOauth2Proxy.On("TokenSource", mock.Anything, oldToken).Return(tokenSource).Once()

	newTokenBytes := []byte("serialized-new-token")
	mockSer.On("Marshal", mock.AnythingOfType("*oauth2.Token")).Return(newTokenBytes, nil).Once()
	mockAes.On("Encrypt", newTokenBytes).Return("encrypted-new-token", nil).Once()

	config.RefreshToken(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "access_token", cookie.Name)
	assert.Equal(t, "encrypted-new-token", cookie.Value)

	mockAes.AssertExpectations(t)
	mockSer.AssertExpectations(t)
	mockOauth2Proxy.AssertExpectations(t)
}
