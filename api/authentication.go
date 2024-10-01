package api

import (
	"net/http"
)

type Authtentication interface {
	Login(w http.ResponseWriter, r *http.Request)
	LoginCallback(w http.ResponseWriter, r *http.Request)
	RefreshToken(w http.ResponseWriter, r *http.Request)
}

func SetupRoutes(a Authtentication, RedirectURL string) {
	http.HandleFunc("/login", a.Login)
	http.HandleFunc("/login/callback", a.LoginCallback)
}
