package service

import "AuthService/internal/models"

type IAuthService interface {
	Register(username, email, password string) (*models.User, string, error)
	Login(username, password string) (*models.User, string, error)
	ValidateToken(token string) (*models.User, error)
} 