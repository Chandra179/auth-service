/*
Package oidc provides an abstraction over the OpenID Connect (OIDC) client implementation
using the `go-oidc` library from CoreOS. This package defines an interface for OIDC
operations, allowing for easy mocking in unit tests and cleaner integration with
OIDC providers.

This package includes the following components:

- OIDCClient interface: Defines methods for working with OIDC tokens and providers.
- OIDC struct: Implements the OIDCClient interface and encapsulates the OIDC provider.
*/

// Package oidc provides an abstraction over the OpenID Connect (OIDC) client implementation.
package oidc

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCClient defines the methods for interacting with OIDC tokens and providers.
// This interface can be implemented or mocked for testing purposes.
type OIDCClient interface {
	// Verifier returns an IDTokenVerifier for verifying ID tokens.
	Verifier(clientID string) *oidc.IDTokenVerifier

	// Verify verifies the provided raw ID token and returns the IDToken if valid.
	Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error)

	// Claims extracts claims from the IDToken into the provided structure.
	Claims(idToken *oidc.IDToken, v interface{}) error

	// VerifyAccessToken verifies the access token associated with the IDToken.
	VerifyAccessToken(idToken *oidc.IDToken, accessToken string) error

	// NewProvider initializes a new OIDC provider for the given issuer.
	// Call this first before calling other method
	NewProvider(ctx context.Context, issuer string) error

	// IsEmailVerified checks if the user's email is verified.
	IsEmailVerified(isVerified bool) bool
}

// OIDC is a struct that implements the OIDCClient interface and encapsulates the OIDC provider.
type OIDC struct {
	Provider *oidc.Provider // The underlying OIDC provider.
}

// NewOIDCClient creates and returns a new instance of the OIDC struct.
func NewOIDCClient() *OIDC {
	return &OIDC{}
}

// Verifier returns an IDTokenVerifier for verifying ID tokens associated with the specified client ID.
func (o *OIDC) Verifier(clientID string) *oidc.IDTokenVerifier {
	return o.Provider.Verifier(&oidc.Config{ClientID: clientID})
}

// Verify verifies the provided raw ID token using the specified verifier.
// It returns the verified IDToken or an error if the verification fails.
func (o *OIDC) Verify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken string) (*oidc.IDToken, error) {
	return verifier.Verify(ctx, rawIDToken)
}

// Claims extracts claims from the IDToken into the provided structure.
// It returns an error if the claims extraction fails.
func (o *OIDC) Claims(idToken *oidc.IDToken, v interface{}) error {
	return idToken.Claims(v)
}

// VerifyAccessToken verifies the access token associated with the IDToken.
// It returns an error if the verification fails.
func (o *OIDC) VerifyAccessToken(idToken *oidc.IDToken, accessToken string) error {
	return idToken.VerifyAccessToken(accessToken)
}

// IsEmailVerified checks if the user's email is verified.
// Returns true if the email is verified, otherwise false.
func (o *OIDC) IsEmailVerified(isVerified bool) bool {
	return isVerified
}

// NewProvider initializes a new OIDC provider for the given issuer.
// It returns an error if the provider cannot be created.
func (o *OIDC) NewProvider(ctx context.Context, issuer string) error {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return err
	}
	o.Provider = provider
	return nil
}
