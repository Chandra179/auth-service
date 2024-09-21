package internal

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Chandra179/oauth2-service/configs"
)

func StartServer() {
	// Configs
	config, err := configs.LoadConfig()
	if err != nil {
		fmt.Println("err")
	}
	// Logger
	logger := log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	// GoogleOauth2
	googleOauth := NewGoogleOauth(config, NewStateStore(), NewTokenStore(), logger)
	googleOauth.SetupRoutes()
	// Http Server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
