package internal

import (
	"context"

	"golang.org/x/oauth2"
)

type Oauth2Proxy interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Extra(key string) interface{}
}

type Oauth2 struct{}

func (o *Oauth2) Exchange(ctx context.Context, cfg *oauth2.Config, code string, opt oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return cfg.Exchange(ctx, code, opt)
}

func (o *Oauth2) Extra(key string, oauth2Token *oauth2.Token) interface{} {
	return oauth2Token.Extra("id_token").(string)
}
