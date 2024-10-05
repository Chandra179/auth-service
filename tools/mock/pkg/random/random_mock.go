package random

import (
	"github.com/stretchr/testify/mock"
)

type MockRandom struct {
	mock.Mock
}

func (m *MockRandom) GenerateRandomString(byteLen int64) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
