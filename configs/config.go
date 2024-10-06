package configs

import (
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	Oauth2Cfg    oauth2.Config
	Oauth2Issuer string
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file")
	}

	return &Config{
		Oauth2Cfg: oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			Endpoint:     google.Endpoint,
		},
		Oauth2Issuer: os.Getenv("OIDC_ISSUER"),
	}, nil
}
