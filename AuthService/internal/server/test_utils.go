package server

import (
	"AuthService/internal/repository"
	"AuthService/internal/service"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *service.AuthService) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	authService := service.NewAuthService(userRepo)
	return db, mock, authService
} 