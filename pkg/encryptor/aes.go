package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type AesOperations interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}

// AesEncryptor implements the Encryptor interface using AES.
type AesEncryptor struct {
	key []byte
}

// NewAesEncryptor creates a new AesEncryptor with the given key.
func NewAesEncryptor(key string) (*AesEncryptor, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, fmt.Errorf("key must be 16, 24, or 32 bytes long")
	}
	return &AesEncryptor{key: keyBytes}, nil
}

// Encrypt encrypts plaintext using AES and returns a base64 encoded string.
func (e *AesEncryptor) Encrypt(plaintext []byte) (string, error) {
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

// Decrypt decrypts a base64 encoded ciphertext back to plaintext using AES.
func (e *AesEncryptor) Decrypt(ciphertext string) ([]byte, error) {
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
