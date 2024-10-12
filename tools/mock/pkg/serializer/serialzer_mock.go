package serializer

import (
	"github.com/stretchr/testify/mock"
)

type MockSerialization struct {
	mock.Mock
}

func (m *MockSerialization) Marshal(v interface{}) ([]byte, error) {
	args := m.Called(v)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerialization) Unmarshal(data []byte, v interface{}) error {
	args := m.Called(data, v)
	return args.Error(0)
}
