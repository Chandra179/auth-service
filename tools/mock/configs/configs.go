package configs

import (
	"github.com/Chandra179/auth-service/configs"
	"github.com/stretchr/testify/mock"
)

// Mock Configs
type MockConfigs struct {
	mock.Mock
}

func (m *MockConfigs) GetProviderConfig(name string, cfg *configs.AppConfig) (*configs.Oauth2Provider, error) {
	args := m.Called(name, cfg)
	return args.Get(0).(*configs.Oauth2Provider), args.Error(1)
}
