package oauth2

import (
	"context"

	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

type MockOauth2Proxy struct {
	mock.Mock
}

func (m *MockOauth2Proxy) S256ChallengeFromVerifier(verifier string) string {
	args := m.Called(verifier)
	return args.String(0)
}

func (m *MockOauth2Proxy) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	args := m.Called(state, opts)
	return args.String(0)
}

func (m *MockOauth2Proxy) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	args := m.Called(ctx, code, opts)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockOauth2Proxy) Extra(key string, token *oauth2.Token) interface{} {
	args := m.Called(key, token)
	return args.Get(0)
}

func (m *MockOauth2Proxy) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	args := m.Called(ctx, t)
	return args.Get(0).(oauth2.TokenSource)
}
