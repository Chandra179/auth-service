package encryption

import (
	"github.com/stretchr/testify/mock"
)

// Mock AesEncryptor
type MockAesEncryptor struct {
	mock.Mock
}

func (m *MockAesEncryptor) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *MockAesEncryptor) Decrypt(encryptedData string) ([]byte, error) {
	args := m.Called(encryptedData)
	return args.Get(0).([]byte), args.Error(1)
}
