package random

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type RandomOperations interface {
	GenerateRandomString() (string, error)
}

type Random struct {
	byteLen int64
}

func NewRandom(byteLen int64) *Random {
	return &Random{byteLen: byteLen}
}

func (r *Random) GenerateRandomString() (string, error) {
	b := make([]byte, r.byteLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
