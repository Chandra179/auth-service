package internal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chandra179/auth-service/configs"
	configsmock "github.com/Chandra179/auth-service/tools/mock/configs"
	"github.com/Chandra179/auth-service/tools/mock/pkg/encryption"
	oauth2mock "github.com/Chandra179/auth-service/tools/mock/pkg/oauth2"
	oidcmock "github.com/Chandra179/auth-service/tools/mock/pkg/oidc"
	"github.com/Chandra179/auth-service/tools/mock/pkg/random"
	"github.com/Chandra179/auth-service/tools/mock/pkg/redis"
	"github.com/Chandra179/auth-service/tools/mock/pkg/serializer"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestLogin_WhenAllSystemsOperational_ShouldRedirectToAuthProvider(t *testing.T) {
	// Setup
	mockRandom := &random.MockRandom{}
	mockRedis := &redis.MockRedisClient{}
	mockOauth2Client := &oauth2mock.MockOauth2Client{}
	mockSerializer := &serializer.MockSerialization{}
	mockConfigsInterface := &configsmock.MockConfigs{}
	oauth2State := []byte("encoded_state")

	config := &Oauth2Service{
		randomGen:    mockRandom,
		cacheStore:   mockRedis,
		oauth2Client: mockOauth2Client,
		serializer:   mockSerializer,
		config:       mockConfigsInterface,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login/google", nil)

	mockConfigsInterface.On("GetProviderConfig", "google").Return(&configs.Oauth2Provider{}, nil).Once()
	mockOauth2Client.On("SetConfig", mock.Anything).Return()
	mockRandom.On("String", int64(32)).Return("abcd", nil).Times(2)
	mockSerializer.On("Encode", mock.MatchedBy(func(as *AuthState) bool {
		return as.Verifier == "abcd" && as.Provider == "google"
	})).Return(oauth2State, nil).Once()
	mockRedis.On("Set", "abcd", oauth2State, 5*time.Minute).Return(nil).Once()

	actualChallenge := "iNQmb9TmM40TuEX88olXnSCciXgjuSF9o-Fhk28DFYk"
	mockOauth2Client.On("S256ChallengeFromVerifier", "abcd").Return(actualChallenge).Once()

	expectedURL := fmt.Sprintf("/login/?access_type=offline&client_id=&code_challenge=%s&code_challenge_method=S256&include_granted_scopes=true&response_type=code&state=abcd", actualChallenge)
	mockOauth2Client.On("AuthCodeURL", "abcd", []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", actualChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}).Return(expectedURL).Once()

	// Act
	config.InitiateLogin(w, r)

	// Assert
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, expectedURL, w.Header().Get("Location"))

	mockRandom.AssertExpectations(t)
	mockSerializer.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
	mockOauth2Client.AssertExpectations(t)
}

func TestLoginCallback_WhenValidStateAndCode_ShouldSetAccessTokenCookie(t *testing.T) {
	// Setup
	mockRandom := &random.MockRandom{}
	mockRedis := &redis.MockRedisClient{}
	mockOauth2Client := &oauth2mock.MockOauth2Client{}
	mockOIDCClient := &oidcmock.MockOIDCClient{}
	mockSerializer := &serializer.MockSerialization{}
	mockEncryptor := &encryption.MockAesEncryptor{}
	mockConfigsInterface := &configsmock.MockConfigs{}

	config := &Oauth2Service{
		cacheStore:   mockRedis,
		oauth2Client: mockOauth2Client,
		oidcClient:   mockOIDCClient,
		serializer:   mockSerializer,
		encryptor:    mockEncryptor,
		randomGen:    mockRandom,
		config:       mockConfigsInterface,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=state123&code=code123", nil)

	token := &oauth2.Token{AccessToken: "access123"}
	storedState := []byte("stored-state")
	rawIDToken := "raw-id-token"
	verifier := &oidc.IDTokenVerifier{}
	idToken := &oidc.IDToken{}
	oauth2Provider := &configs.Oauth2Provider{
		Oauth2Issuer: "https://accounts.google.com",
		Oauth2Config: oauth2.Config{
			RedirectURL: "http://localhost:8080/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		},
	}

	mockRedis.On("Get", "state123").Return(storedState, nil)
	mockSerializer.On("Decode", storedState, mock.AnythingOfType("*internal.AuthState")).Return(nil)
	mockConfigsInterface.On("GetProviderConfig", mock.Anything).Return(oauth2Provider, nil)
	mockOauth2Client.On("SetConfig", mock.Anything).Return()
	mockOIDCClient.On("NewProvider", r.Context(), oauth2Provider.Oauth2Issuer).Return(nil)
	mockOauth2Client.On("Exchange", mock.Anything, "code123", mock.Anything).Return(token, nil)
	mockOauth2Client.On("Extra", "id_token", token).Return(rawIDToken)
	mockOIDCClient.On("Verifier", oauth2Provider.Oauth2Config.ClientID).Return(verifier)
	mockOIDCClient.On("Verify", r.Context(), verifier, rawIDToken).Return(idToken, nil)
	mockOIDCClient.On("VerifyAccessToken", idToken, token.AccessToken).Return(nil)
	mockOIDCClient.On("Claims", idToken, mock.AnythingOfType("*internal.UserProfile")).Return(nil)
	mockOIDCClient.On("IsEmailVerified", mock.Anything).Return(true)

	tokenBytes := []byte("serialized-token")
	mockSerializer.On("Encode", token).Return(tokenBytes, nil)
	mockEncryptor.On("Encrypt", tokenBytes).Return("encrypted-token", nil)

	config.HandleLoginCallback(w, r)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/success", w.Header().Get("Location"))

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.Equal(t, "encrypted-token", cookie.Value)

	mockRedis.AssertExpectations(t)
	mockOauth2Client.AssertExpectations(t)
	mockOIDCClient.AssertExpectations(t)
	mockSerializer.AssertExpectations(t)
	mockEncryptor.AssertExpectations(t)
	mockConfigsInterface.AssertExpectations(t)
}
