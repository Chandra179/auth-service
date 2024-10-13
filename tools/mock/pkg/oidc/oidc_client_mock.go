package oidc

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/mock"
)

type MockOIDCClient struct {
	mock.Mock
}

func (m *MockOIDCClient) Verifier(clientID string) *oidc.IDTokenVerifier {
	args := m.Called(clientID)
	return args.Get(0).(*oidc.IDTokenVerifier)
}

func (m *MockOIDCClient) Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error) {
	args := m.Called(ctx, verifier, rawIDToken)
	return args.Get(0).(*oidc.IDToken), args.Error(1)
}

func (m *MockOIDCClient) Claims(idToken *oidc.IDToken, claims interface{}) error {
	args := m.Called(idToken, claims)
	return args.Error(0)
}

func (m *MockOIDCClient) VerifyAccessToken(idToken *oidc.IDToken, accessToken string) error {
	args := m.Called(idToken, accessToken)
	return args.Error(0)
}

func (m *MockOIDCClient) NewProvider(ctx context.Context, issuer string) error {
	args := m.Called(ctx, issuer)
	return args.Error(0)
}

func (m *MockOIDCClient) IsEmailVerified(i bool) bool {
	args := m.Called(i)
	return args.Bool(0)
}
