package internal

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryptor"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serialization"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type OAuthState struct {
	State    string
	Verifier string
	Created  time.Time
}

type GoogleOauth struct {
	config   *oauth2.Config
	logger   *log.Logger
	limiter  *rate.Limiter
	redisOpr redis.RedisOperations
	aes      encryptor.AesOperations
	ser      serialization.SerializationOperations
	rand     random.RandomOperations
}

func NewGoogleOauth(cfg *configs.Config, redisOpr redis.RedisOperations, logger *log.Logger,
	aes encryptor.AesOperations, ser serialization.SerializationOperations, rand random.RandomOperations) *GoogleOauth {
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.GoogleOauth.ClientID,
		ClientSecret: cfg.GoogleOauth.ClientSecret,
		RedirectURL:  cfg.GoogleOauth.RedirectURL,
		Scopes:       cfg.GoogleOauth.Scopes,
		Endpoint:     cfg.GoogleOauth.Endpoint,
	}

	return &GoogleOauth{
		config:   oauth2Config,
		redisOpr: redisOpr,
		logger:   logger,
		aes:      aes,
		limiter:  rate.NewLimiter(rate.Every(time.Second), 10), // 10 requests per second
		ser:      ser,
		rand:     rand,
	}
}

func (g *GoogleOauth) Login(w http.ResponseWriter, r *http.Request) {
	if !g.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state, err := g.rand.GenerateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}
	verifier, err := g.rand.GenerateRandomString()
	if err != nil {
		http.Error(w, "Failed to generate rand string", http.StatusInternalServerError)
		return
	}

	// temporary store state in redis, state will be used for LoginCallback state validation
	// assuming will receive the callback within 5 minute after login
	g.redisOpr.Set(state, verifier, 5*time.Minute)

	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	authURL := g.config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	g.logger.Printf("Generated auth URL: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Token represents the structure of the Google Token
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
}

func (g *GoogleOauth) LoginCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if !g.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state := r.URL.Query().Get("state")
	oauthState, exists := g.redisOpr.Get(state)
	if exists != nil {
		g.logger.Printf("Invalid state received: %s", state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	g.redisOpr.Delete(state)

	code := r.URL.Query().Get("code")
	token, err := g.config.Exchange(ctx, code, oauth2.VerifierOption(oauthState))
	if err != nil {
		g.logger.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	tokenJson := Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		ExpiresIn:    token.ExpiresIn,
	}

	byteCode, err := g.ser.Marshal(tokenJson)
	if err != nil {
		http.Error(w, "Failed to serializa token", http.StatusInternalServerError)
	}

	encryptedCode, err := g.aes.Encrypt(byteCode)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
	}

	// Set the HTTP-only and secure cookies for access and refresh tokens
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    encryptedCode, // consist of (access_token, refresh, expired, etc..)
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                    // Ensure this is set to true when using HTTPS
		SameSite: http.SameSiteStrictMode, // Adjust as per your requirements
	})

	g.logger.Printf("Token successfully exchanged and stored")
	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (g *GoogleOauth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cookie, err := r.Cookie("access_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Cookie not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Error retrieving cookie", http.StatusInternalServerError)
		return
	}

	tokenByte, err := g.aes.Decrypt(cookie.Value)
	if err != nil {
		http.Error(w, "Error decrypting token", http.StatusInternalServerError)
		return
	}

	token := &oauth2.Token{}
	err = g.ser.Unmarshal(tokenByte, token)
	if err != nil {
		http.Error(w, "Error deserealize token", http.StatusInternalServerError)
		return
	}

	newToken, err := g.config.TokenSource(ctx, token).Token()
	if err != nil {
		http.Error(w, "Refresh token failed", http.StatusInternalServerError)
		return
	}

	tokenJson := Token{
		AccessToken:  newToken.AccessToken,
		TokenType:    newToken.TokenType,
		RefreshToken: newToken.RefreshToken,
		Expiry:       newToken.Expiry,
		ExpiresIn:    newToken.ExpiresIn,
	}
	byteCode, err := g.ser.Marshal(tokenJson)
	if err != nil {
		http.Error(w, "Failed to serializa token", http.StatusInternalServerError)
	}

	encryptedCode, err := g.aes.Encrypt(byteCode)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    encryptedCode, // consist of (access_token, refresh, expired, etc..)
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                    // Ensure this is set to true when using HTTPS
		SameSite: http.SameSiteStrictMode, // Adjust as per your requirements
	})
}
