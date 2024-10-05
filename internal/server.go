package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Chandra179/auth-service/api"
	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/random"
)

func StartServer() {
	// -------------
	// Configs
	// -------------
	config, err := configs.LoadConfig()
	if err != nil {
		fmt.Println("err config", err)
	}
	// --------------
	// Logger
	// --------------
	// logger := log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	// // --------------
	// // Serialization
	// // --------------
	// ser := serialization.NewGobSerialization()
	// // --------------
	// // Enryption
	// // --------------
	// aes, err := encryptor.NewAesEncryptor("0123456789abcdef") //16 bytes key
	// if err != nil {
	// 	fmt.Println("encryption err", err)
	// }
	// --------------
	// Random
	// --------------
	rand := random.NewRandom(32)
	// --------------
	// Oauth
	// --------------
	oidc, err := NewOIDCConfig(context.Background(), &config.Oauth2Cfg, config.Issuer, rand)
	if err != nil {
		fmt.Println("oidc initializatin failed", err)
	}
	// --------------
	// API setup
	// --------------
	api.SetupRoutes(oidc, config.Oauth2Cfg.RedirectURL)
	//---------------
	// Http Server
	// --------------
	log.Fatal(http.ListenAndServe(":8080", nil))
}
