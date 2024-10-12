package configs

import (
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Oauth2Provider struct {
	Oauth2Config oauth2.Config
	Oauth2Issuer string
}

type AppConfig struct {
	GoogleOauth2Cfg    *Oauth2Provider
	MicrosoftOauth2Cfg *Oauth2Provider
}

func LoadConfig() (*AppConfig, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file")
	}

	return &AppConfig{
		GoogleOauth2Cfg: &Oauth2Provider{
			Oauth2Config: oauth2.Config{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
				Endpoint:     google.Endpoint,
			},
			Oauth2Issuer: os.Getenv("GOOGLE_OIDC_ISSUER"),
		},
		MicrosoftOauth2Cfg: &Oauth2Provider{
			Oauth2Config: oauth2.Config{
				ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
				ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
				RedirectURL:  os.Getenv("MICROSOFT_REDIRECT_URL"),
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
				Endpoint:     google.Endpoint,
			},
			Oauth2Issuer: os.Getenv("MICROSOFT_OIDC_ISSUER"),
		},
	}, nil
}

// GetProvider returns a provider configuration by name
func (c *AppConfig) GetProviderConfig(name string, cfg *AppConfig) (*Oauth2Provider, error) {
	if name == "google" {
		return cfg.GoogleOauth2Cfg, nil
	}
	if name == "microsoft" {
		return cfg.GoogleOauth2Cfg, nil
	}
	return nil, fmt.Errorf("unsupported provider: %s", name)
}
