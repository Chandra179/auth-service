package oidc

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCClient interface {
	Verifier(clientID string) *oidc.IDTokenVerifier
	Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error)
	Claims(idToken *oidc.IDToken, v interface{}) error
	VerifyAccessToken(idToken *oidc.IDToken, accessToken string) error
	NewProvider(ctx context.Context, issuer string) error
	IsEmailVerified(isVerified bool) bool
}

type OIDC struct {
	Provider *oidc.Provider
}

func NewOIDCClient() *OIDC {
	return &OIDC{}
}

func (o *OIDC) Verifier(clientID string) *oidc.IDTokenVerifier {
	return o.Provider.Verifier(&oidc.Config{ClientID: clientID})
}

func (o *OIDC) Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error) {
	return verifier.Verify(ctx, rawIDToken)
}

func (o *OIDC) Claims(idToken *oidc.IDToken, v interface{}) error {
	return idToken.Claims(v)
}

func (o *OIDC) VerifyAccessToken(idToken *oidc.IDToken, accessToken string) error {
	return idToken.VerifyAccessToken(accessToken)
}

func (o *OIDC) IsEmailVerified(isVerified bool) bool {
	return isVerified
}

func (o *OIDC) NewProvider(ctx context.Context, issuer string) error {
	povider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return err
	}
	o.Provider = povider
	return nil
}
