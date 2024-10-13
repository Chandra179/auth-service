package oauth2

import (
	"context"

	"golang.org/x/oauth2"
)

type Oauth2Client interface {
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	Extra(key string, oauth2Token *oauth2.Token) interface{}
	S256ChallengeFromVerifier(verifier string) string
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
	SetConfig(cfg *oauth2.Config)
}

type Oauth2 struct {
	Cfg *oauth2.Config
}

func NewOauth2Client() *Oauth2 {
	return &Oauth2{}
}

func (o *Oauth2) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	opts := oauth2.VerifierOption(verifier)
	return o.Cfg.Exchange(ctx, code, opts)
}

func (o *Oauth2) Extra(key string, oauth2Token *oauth2.Token) interface{} {
	return oauth2Token.Extra("id_token").(string)
}

func (o *Oauth2) S256ChallengeFromVerifier(verifier string) string {
	return oauth2.S256ChallengeFromVerifier(verifier)
}

func (o *Oauth2) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return o.Cfg.AuthCodeURL(state, opts...)
}

func (o *Oauth2) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	return o.Cfg.TokenSource(ctx, t)
}

func (o *Oauth2) SetConfig(cfg *oauth2.Config) {
	o.Cfg = cfg
}
