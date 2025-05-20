package service

import (
	"errors"
	"testing"
	_"time"

	"AuthService/internal/models"
	_"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type mockUserRepo struct {
	CreateUserFunc      func(user *models.User) error
	GetUserByIDFunc     func(id int) (*models.User, error)
	GetUserByUsernameFunc func(username string) (*models.User, error)
	UserExistsFunc      func(username string) (bool, error)
	GetUserRoleFunc     func(userID int) (string, error)
}

func (m *mockUserRepo) CreateUser(user *models.User) error {
	return m.CreateUserFunc(user)
}
func (m *mockUserRepo) GetUserByID(id int) (*models.User, error) {
	return m.GetUserByIDFunc(id)
}
func (m *mockUserRepo) GetUserByUsername(username string) (*models.User, error) {
	return m.GetUserByUsernameFunc(username)
}
func (m *mockUserRepo) UserExists(username string) (bool, error) {
	return m.UserExistsFunc(username)
}
func (m *mockUserRepo) GetUserRole(userID int) (string, error) {
	return m.GetUserRoleFunc(userID)
}

func TestRegister_Success(t *testing.T) {
	repo := &mockUserRepo{
		UserExistsFunc: func(username string) (bool, error) { return false, nil },
		CreateUserFunc: func(user *models.User) error {
			user.ID = 1
			return nil
		},
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Register("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.NotEmpty(t, token)
}

func TestRegister_UserExists(t *testing.T) {
	repo := &mockUserRepo{
		UserExistsFunc: func(username string) (bool, error) { return true, nil },
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Register("testuser", "password123")
	assert.ErrorIs(t, err, ErrUserAlreadyExists)
	assert.Nil(t, user)
	assert.Empty(t, token)
}

func TestRegister_CreateUserError(t *testing.T) {
	repo := &mockUserRepo{
		UserExistsFunc: func(username string) (bool, error) { return false, nil },
		CreateUserFunc: func(user *models.User) error { return errors.New("db error") },
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Register("testuser", "password123")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Empty(t, token)
}

func TestLogin_Success(t *testing.T) {
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	repo := &mockUserRepo{
		GetUserByUsernameFunc: func(username string) (*models.User, error) {
			return &models.User{ID: 1, Username: username, Password: string(hashed), Role: "user"}, nil
		},
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Login("testuser", "password123")
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.NotEmpty(t, token)
}

func TestLogin_UserNotFound(t *testing.T) {
	repo := &mockUserRepo{
		GetUserByUsernameFunc: func(username string) (*models.User, error) {
			return nil, errors.New("not found")
		},
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Login("nouser", "password123")
	assert.ErrorIs(t, err, ErrUserNotFound)
	assert.Nil(t, user)
	assert.Empty(t, token)
}

func TestLogin_InvalidPassword(t *testing.T) {
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	repo := &mockUserRepo{
		GetUserByUsernameFunc: func(username string) (*models.User, error) {
			return &models.User{ID: 1, Username: username, Password: string(hashed), Role: "user"}, nil
		},
	}
	svc := NewAuthService(repo)
	user, token, err := svc.Login("testuser", "wrongpass")
	assert.ErrorIs(t, err, ErrInvalidPassword)
	assert.Nil(t, user)
	assert.Empty(t, token)
}

func TestValidateToken_Success(t *testing.T) {
	repo := &mockUserRepo{
		GetUserByIDFunc: func(id int) (*models.User, error) {
			return &models.User{ID: uint(id), Username: "testuser", Role: "user"}, nil
		},
	}
	svc := NewAuthService(repo)
	user := &models.User{ID: 42, Username: "testuser", Role: "user"}
	token, err := svc.generateToken(user)
	require.NoError(t, err)
	gotUser, err := svc.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, gotUser.ID)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewAuthService(repo)
	_, err := svc.ValidateToken("badtoken")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_UserNotFound(t *testing.T) {
	repo := &mockUserRepo{
		GetUserByIDFunc: func(id int) (*models.User, error) {
			return nil, errors.New("not found")
		},
	}
	svc := NewAuthService(repo)
	user := &models.User{ID: 42, Username: "testuser", Role: "user"}
	token, err := svc.generateToken(user)
	require.NoError(t, err)
	gotUser, err := svc.ValidateToken(token)
	assert.ErrorIs(t, err, ErrUserNotFound)
	assert.Nil(t, gotUser)
} 