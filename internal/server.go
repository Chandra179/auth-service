package internal

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Chandra179/auth-service/api"
	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/encryptor"
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
		fmt.Println("err")
	}
	// --------------
	// Logger
	// --------------
	logger := log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	// --------------
	// Redis
	// --------------
	rdb := redis.NewRedisClient("localhost:6379", "", 0)
	// --------------
	// Serialization
	// --------------
	ser := serialization.NewSerializationManager(&serialization.GobSerializer{})
	// --------------
	// Enryption
	// --------------
	aes, err := encryptor.NewAesEncryptor("replace_this_key_with_symetric_key_encryption")
	if err != nil {
		fmt.Println("err")
	}
	// --------------
	// Random
	// --------------
	rand := random.NewRandom(32)
	// --------------
	// Oauth
	// --------------
	googleOauth := NewGoogleOauth(config, rdb, logger, aes, ser, rand)
	// --------------
	// API setup
	// --------------
	api.SetupRoutes(googleOauth, config.GoogleOauth.RedirectURL)
	//---------------
	// Http Server
	// --------------
	log.Fatal(http.ListenAndServe(":8080", nil))
}
