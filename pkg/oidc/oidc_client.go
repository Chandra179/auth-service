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
}

type OIDC struct {
	provider *oidc.Provider
}

func NewOIDCClient(ctx context.Context, issuer string) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &OIDC{
		provider: provider,
	}, nil
}

func (o *OIDC) Verifier(clientID string) *oidc.IDTokenVerifier {
	return o.provider.Verifier(&oidc.Config{ClientID: clientID})
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
