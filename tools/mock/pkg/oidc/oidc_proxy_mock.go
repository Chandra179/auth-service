package oidc

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/mock"
)

type MockOIDCProxy struct {
	mock.Mock
}

func (m *MockOIDCProxy) Verifier(clientID string) *oidc.IDTokenVerifier {
	args := m.Called(clientID)
	return args.Get(0).(*oidc.IDTokenVerifier)
}

func (m *MockOIDCProxy) Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error) {
	args := m.Called(ctx, verifier, rawIDToken)
	return args.Get(0).(*oidc.IDToken), args.Error(1)
}

func (m *MockOIDCProxy) Claims(idToken *oidc.IDToken, claims interface{}) error {
	args := m.Called(idToken, claims)
	return args.Error(0)
}
