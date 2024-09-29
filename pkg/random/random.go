package random

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func NewRandom(byteLen int64) *Random {
	return &Random{byteLen: byteLen}
}

type Random struct {
	byteLen int64
}

func (r *Random) GenerateRandomString() (string, error) {
	b := make([]byte, r.byteLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
