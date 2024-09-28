package internal

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Chandra179/auth-service/api"
	"github.com/Chandra179/auth-service/configs"
	"github.com/Chandra179/auth-service/pkg/redis"
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
	// Oauth
	// --------------
	googleOauth := NewGoogleOauth(config, rdb, logger)
	// --------------
	// API setup
	// --------------
	api.SetupRoutes(googleOauth, config.GoogleOauth.RedirectURL)
	//---------------
	// Http Server
	// --------------
	log.Fatal(http.ListenAndServe(":8080", nil))
}
