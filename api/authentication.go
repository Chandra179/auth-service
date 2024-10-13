package api

import (
	"net/http"
)

type Authtentication interface {
	InitiateLogin(w http.ResponseWriter, r *http.Request)
	HandleLoginCallback(w http.ResponseWriter, r *http.Request)
	RefreshToken(w http.ResponseWriter, r *http.Request)
}

func SetupRoutes(a Authtentication) {
	http.HandleFunc("/login/", a.InitiateLogin)
	http.HandleFunc("/login/callback", a.HandleLoginCallback)
	http.HandleFunc("/refresh", a.RefreshToken)
}
