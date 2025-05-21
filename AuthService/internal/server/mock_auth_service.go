package server

import (
	"AuthService/internal/models"
	"AuthService/internal/service"
	"github.com/stretchr/testify/mock"
)

var _ service.IAuthService = (*MockAuthService)(nil)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(username, email, password string) (*models.User, string, error) {
	args := m.Called(username, email, password)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*models.User), args.String(1), args.Error(2)
}

func (m *MockAuthService) Login(username, password string) (*models.User, string, error) {
	args := m.Called(username, password)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*models.User), args.String(1), args.Error(2)
}

func (m *MockAuthService) ValidateToken(token string) (*models.User, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
} 