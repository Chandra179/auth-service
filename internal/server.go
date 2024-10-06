package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Chandra179/auth-service/api"
	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryptor"
	"github.com/Chandra179/auth-service/pkg/oauth2"
	"github.com/Chandra179/auth-service/pkg/oidc"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serialization"
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
	// Redis
	// --------------
	rdb := redis.NewRedisClient("redis:6379", "", 0)
	// --------------
	// Serialization
	// --------------
	ser := serialization.NewGobSerialization()
	// --------------
	// Enryption
	// --------------
	aes, err := encryptor.NewAesEncryptor("0123456789abcdef") //16 bytes key
	if err != nil {
		fmt.Println("encryption err", err)
	}
	// --------------
	// Random
	// --------------
	rand := random.NewRandom()
	// --------------
	// Authentication
	// --------------
	oidc, err := oidc.NewOIDC(context.Background(), config.Oauth2Issuer)
	if err != nil {
		fmt.Println("oidc initialize err", err)
	}
	oauth2 := oauth2.NewOauth2(&config.Oauth2Cfg)

	auth, err := NewAuthentication(context.Background(), &config.Oauth2Cfg, rand, aes, ser, rdb, oidc, oauth2)
	if err != nil {
		fmt.Println("oidc initializatin failed", err)
	}
	// --------------
	// API setup
	// --------------
	api.SetupRoutes(auth)
	//---------------
	// Http Server
	// --------------
	log.Fatal(http.ListenAndServe(":8080", nil))
}
