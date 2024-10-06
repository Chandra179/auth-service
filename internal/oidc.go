package internal

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCProxy interface {
	NewProvider(ctx context.Context, issuer string) (*oidc.Provider, error)
	Verifier(provider *oidc.Provider, clientID string) *oidc.IDTokenVerifier
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
	Claims(v interface{}) error
}

type OIDC struct{}

func (o *OIDC) NewProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return oidc.NewProvider(ctx, issuer)
}

func (o *OIDC) Verifier(provider *oidc.Provider, clientID string) *oidc.IDTokenVerifier {
	return provider.Verifier(&oidc.Config{ClientID: clientID})
}

func (o *OIDC) Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error) {
	return verifier.Verify(ctx, rawIDToken)
}

func (o *OIDC) Claims(idToken *oidc.IDToken, v interface{}) error {
	return idToken.Claims(v)
}
