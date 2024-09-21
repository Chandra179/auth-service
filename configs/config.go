package configs

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	GoogleOauth oauth2.Config
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file")
	}

	return &Config{
		GoogleOauth: oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes: []string{
				os.Getenv("GOOGLE_SCOPES"),
			},
			Endpoint: google.Endpoint,
		},
	}, nil
}
