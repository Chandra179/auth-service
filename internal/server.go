package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Chandra179/auth-service/api"
	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryption"
	"github.com/Chandra179/auth-service/pkg/oauth2"
	"github.com/Chandra179/auth-service/pkg/oidc"
	"github.com/Chandra179/auth-service/pkg/random"
	"github.com/Chandra179/auth-service/pkg/redis"
	"github.com/Chandra179/auth-service/pkg/serializer"
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
	ser := serializer.NewGobSerialization()
	// --------------
	// Enryption
	// --------------
	aes, err := encryption.NewAesEncryptor("0123456789abcdef") //16 bytes key
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
	oidc := oidc.NewOIDCClient()
	oauth2 := oauth2.NewOauth2Client()
	auth, err := NewOauth2Service(context.Background(), config, rand, aes, ser, rdb, oidc, oauth2)
	if err != nil {
		fmt.Println("Oauth2Service initialization failed", err)
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
