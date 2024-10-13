/*
Package encryption provides utilities for encrypting and decrypting data using AES (Advanced Encryption Standard).
It supports encryption of plaintext into base64 encoded ciphertext and decryption of base64 encoded ciphertext back to plaintext.

Components:
- AESEncryptor interface: Defines methods for encrypting and decrypting data.
- Aes struct: Implements the AESEncryptor interface using AES encryption.

Usage:
To use this package, create an instance of Aes using NewAesEncryptor, then call the Encrypt and Decrypt methods
to perform encryption and decryption operations.
*/

// Package encryption provides utilities for encrypting and decrypting data using AES.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AESEncryptor is an interface for encryptors that can encrypt and decrypt data.
type AESEncryptor interface {
	// Encrypt encrypts the provided plaintext and returns a base64 encoded string.
	// Parameters:
	//   - plaintext: The byte slice of plaintext to encrypt.
	// Returns:
	//   - A base64 encoded string of the encrypted data.
	//   - An error if the encryption operation fails.
	Encrypt(plaintext []byte) (string, error)

	// Decrypt decrypts the provided base64 encoded ciphertext back to plaintext.
	// Parameters:
	//   - ciphertext: The base64 encoded string of ciphertext to decrypt.
	// Returns:
	//   - A byte slice containing the decrypted plaintext.
	//   - An error if the decryption operation fails.
	Decrypt(ciphertext string) ([]byte, error)
}

// Aes implements the AESEncryptor interface using AES encryption.
type Aes struct {
	key []byte // The AES key used for encryption and decryption
}

// NewAesEncryptor creates a new Aes encryptor with the given key.
// Parameters:
//   - key: The encryption key as a string, which must be 16, 24, or 32 bytes long.
//
// Returns:
//   - A pointer to the newly created Aes instance.
//   - An error if the key length is invalid.
func NewAesEncryptor(key string) (*Aes, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, fmt.Errorf("key must be 16, 24, or 32 bytes long")
	}
	return &Aes{key: keyBytes}, nil
}

// Encrypt encrypts the provided plaintext using AES and returns a base64 encoded string.
// Parameters:
//   - plaintext: The byte slice of plaintext to encrypt.
//
// Returns:
//   - A base64 encoded string of the encrypted data.
//   - An error if the encryption operation fails.
func (e *Aes) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts the provided base64 encoded ciphertext back to plaintext using AES.
// Parameters:
//   - ciphertext: The base64 encoded string of ciphertext to decrypt.
//
// Returns:
//   - A byte slice containing the decrypted plaintext.
//   - An error if the decryption operation fails.
func (e *Aes) Decrypt(ciphertext string) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decodedText, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(decodedText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, cipherText := decodedText[:nonceSize], decodedText[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}
