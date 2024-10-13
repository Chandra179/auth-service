/*
Package oauth2 provides an abstraction over the OAuth 2.0 client implementation
using the `golang.org/x/oauth2` library. This package defines an interface for OAuth 2.0
operations, enabling easy mocking in unit tests and cleaner integration with
OAuth 2.0 providers.

This package includes the following components:

- Oauth2Client interface: Defines methods for working with OAuth 2.0 tokens and clients.
- Oauth2 struct: Implements the Oauth2Client interface and encapsulates the OAuth 2.0 configuration.
*/

// Package oauth2 provides an abstraction over the OAuth 2.0 client implementation.
package oauth2

import (
	"context"

	"golang.org/x/oauth2"
)

// Oauth2Client defines the methods for interacting with OAuth 2.0 tokens and clients.
// This interface can be implemented or mocked for testing purposes.
type Oauth2Client interface {
	// Exchange exchanges the authorization code for an access token using the provided verifier.
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)

	// Extra retrieves additional information from the OAuth2 token based on the specified key.
	Extra(key string, oauth2Token *oauth2.Token) interface{}

	// S256ChallengeFromVerifier generates a S256 challenge from the provided verifier string.
	S256ChallengeFromVerifier(verifier string) string

	// AuthCodeURL generates the URL for the authorization code flow with the specified state and options.
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string

	// TokenSource returns a TokenSource for the given OAuth2 token.
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource

	// SetConfig sets the OAuth2 configuration for the client.
	// We need to set the oauth configuration first before calling other method
	SetConfig(cfg *oauth2.Config)
}

// Oauth2 is a struct that implements the Oauth2Client interface and encapsulates the OAuth 2.0 configuration.
type Oauth2 struct {
	Cfg *oauth2.Config // The underlying OAuth 2.0 configuration.
}

// NewOauth2Client creates and returns a new instance of the Oauth2 struct.
func NewOauth2Client() *Oauth2 {
	return &Oauth2{}
}

// Exchange exchanges the authorization code for an access token using the specified verifier.
// It returns the access token or an error if the exchange fails.
func (o *Oauth2) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	opts := oauth2.VerifierOption(verifier)
	return o.Cfg.Exchange(ctx, code, opts)
}

// Extra retrieves additional information from the OAuth2 token based on the specified key.
// It returns the extra information or nil if the key does not exist.
func (o *Oauth2) Extra(key string, oauth2Token *oauth2.Token) interface{} {
	return oauth2Token.Extra(key)
}

// S256ChallengeFromVerifier generates a S256 challenge from the provided verifier string.
// This is used for the Proof Key for Code Exchange (PKCE) flow.
func (o *Oauth2) S256ChallengeFromVerifier(verifier string) string {
	return oauth2.S256ChallengeFromVerifier(verifier)
}

// AuthCodeURL generates the URL for the authorization code flow with the specified state and options.
// This URL can be used to redirect users for authentication.
func (o *Oauth2) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return o.Cfg.AuthCodeURL(state, opts...)
}

// TokenSource returns a TokenSource for the given OAuth2 token.
// This can be used to obtain new tokens when the current one expires.
func (o *Oauth2) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	return o.Cfg.TokenSource(ctx, t)
}

// SetConfig sets the OAuth2 configuration for the client.
// This should be called before using other methods of the Oauth2 struct.
func (o *Oauth2) SetConfig(cfg *oauth2.Config) {
	o.Cfg = cfg
}
