package configs

import (
	"github.com/Chandra179/auth-service/configs"
	"github.com/stretchr/testify/mock"
)

// Mock Configs
type MockConfigs struct {
	mock.Mock
}

func (m *MockConfigs) GetOauth2ProviderConfig(name string) (*configs.Oauth2Provider, error) {
	args := m.Called(name)
	return args.Get(0).(*configs.Oauth2Provider), args.Error(1)
}
