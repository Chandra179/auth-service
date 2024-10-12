package random

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type RandomGenerator interface {
	String(byteLen int64) (string, error)
}

type Random struct{}

func NewRandom() *Random {
	return &Random{}
}

func (r *Random) String(byteLen int64) (string, error) {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
