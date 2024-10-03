package random

import (
	"github.com/stretchr/testify/mock"
)

type MockRandom struct {
	mock.Mock
}

func (m *MockRandom) GenerateRandomString() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
