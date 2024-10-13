/*
Package random provides utilities for generating random values, primarily focusing on
cryptographically secure random strings. The design allows for easy extension to support
other types of random data in the future.

Components:
- RandomGenerator interface: Defines methods for generating random values.
- Random struct: Implements the RandomGenerator interface, currently supporting string generation.

Usage:
To use this package, create an instance of the Random struct and call the String method
to generate a random string of the specified length.
*/

// Package random provides utilities for generating random values.
package random

import (
	"crypto/rand"     // For generating cryptographically secure random numbers.
	"encoding/base64" // To encode random bytes as a base64 URL-safe string.
	"fmt"             // For formatting errors.
)

// RandomGenerator defines an interface for generating random values.
// Currently, it supports generating random strings, but can be expanded for other types.
type RandomGenerator interface {
	// String generates a random string of the specified byte length.
	// It returns the generated string and an error if the generation fails.
	String(byteLen int64) (string, error)
}

// Random implements the RandomGenerator interface, providing methods for random string generation.
type Random struct{}

// NewRandom creates and returns a new instance of the Random struct.
// This serves as a factory method for creating Random generators.
func NewRandom() *Random {
	return &Random{}
}

// String generates a cryptographically secure random string of the specified byte length.
// It reads random bytes from the crypto/rand package and encodes them as a base64 URL-safe string.
//
// Parameters:
//   - byteLen: The length (in bytes) of the random string to generate.
//
// Returns:
//   - A randomly generated string encoded in base64 URL-safe format.
//   - An error if the random byte generation fails.
func (r *Random) String(byteLen int64) (string, error) {
	// Create a byte slice of the specified length.
	b := make([]byte, byteLen)

	// Read random bytes from the crypto/rand source into the slice.
	_, err := rand.Read(b)
	if err != nil {
		// Wrap the error for better context and return it.
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}

	// Encode the random bytes as a base64 URL-safe string.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
