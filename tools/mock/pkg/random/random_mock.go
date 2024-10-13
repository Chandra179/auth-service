package random

import (
	"github.com/stretchr/testify/mock"
)

type MockRandom struct {
	mock.Mock
}

func (m *MockRandom) String(byteLen int64) (string, error) {
	args := m.Called(byteLen)
	return args.String(0), args.Error(1)
}
