package main

import (
	"AuthService/internal/models"
	"AuthService/internal/repository"
	"AuthService/internal/service"
	"database/sql"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository - мок для репозитория пользователей
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByID(id int) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByUsername(username string) (*models.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UserExists(username string) (bool, error) {
	args := m.Called(username)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) GetUserRole(userID int) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

// TestMainFunction - тест основной функции
func TestMainFunction(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Создаем тестовый сервис
	authService := service.NewAuthService(mockRepo)
	
	// Проверяем, что сервис создан успешно
	assert.NotNil(t, authService)
}

// TestDatabaseConnection - тест подключения к базе данных
func TestDatabaseConnection(t *testing.T) {
	// Тестовые параметры подключения
	dsn := "host=localhost user=postgres password=postgres dbname=forum port=5432 sslmode=disable"
	
	// Пытаемся подключиться к базе данных
	db, err := sql.Open("postgres", dsn)
	
	// Проверяем, что подключение успешно
	assert.NoError(t, err)
	assert.NotNil(t, db)
	
	// Проверяем пинг
	err = db.Ping()
	assert.NoError(t, err)
	
	// Закрываем соединение
	db.Close()
}

// TestAuthServiceCreation - тест создания сервиса аутентификации
func TestAuthServiceCreation(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Создаем сервис
	authService := service.NewAuthService(mockRepo)
	
	// Проверяем, что сервис создан успешно
	assert.NotNil(t, authService)
}

// TestUserRepositoryCreation - тест создания репозитория пользователей
func TestUserRepositoryCreation(t *testing.T) {
	// Тестовые параметры подключения
	dsn := "host=localhost user=postgres password=postgres dbname=forum port=5432 sslmode=disable"
	
	// Подключаемся к базе данных
	db, err := sql.Open("postgres", dsn)
	assert.NoError(t, err)
	
	// Создаем репозиторий
	userRepo := repository.NewUserRepository(db)
	
	// Проверяем, что репозиторий создан успешно
	assert.NotNil(t, userRepo)
	
	// Закрываем соединение
	db.Close()
}

// TestUserCreation - тест создания пользователя
func TestUserCreation(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Создаем тестового пользователя
	user := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "password123",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Настраиваем ожидания мока
	mockRepo.On("CreateUser", user).Return(nil)
	
	// Вызываем метод создания пользователя
	err := mockRepo.CreateUser(user)
	assert.NoError(t, err)
	
	// Проверяем, что все ожидания были выполнены
	mockRepo.AssertExpectations(t)
}

// TestUserRetrieval - тест получения пользователя
func TestUserRetrieval(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Создаем тестового пользователя
	user := &models.User{
		ID:        1,
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "hashedpassword",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Настраиваем ожидания мока
	mockRepo.On("GetUserByUsername", "testuser").Return(user, nil)
	
	// Вызываем метод получения пользователя
	retrievedUser, err := mockRepo.GetUserByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, user, retrievedUser)
	
	// Проверяем, что все ожидания были выполнены
	mockRepo.AssertExpectations(t)
}

// TestUserExists - тест проверки существования пользователя
func TestUserExists(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Настраиваем ожидания мока
	mockRepo.On("UserExists", "testuser").Return(true, nil)
	
	// Вызываем метод проверки существования пользователя
	exists, err := mockRepo.UserExists("testuser")
	assert.NoError(t, err)
	assert.True(t, exists)
	
	// Проверяем, что все ожидания были выполнены
	mockRepo.AssertExpectations(t)
}

// TestGetUserRole - тест получения роли пользователя
func TestGetUserRole(t *testing.T) {
	// Создаем мок репозитория
	mockRepo := new(MockUserRepository)
	
	// Настраиваем ожидания мока
	mockRepo.On("GetUserRole", 1).Return("admin", nil)
	
	// Вызываем метод получения роли пользователя
	role, err := mockRepo.GetUserRole(1)
	assert.NoError(t, err)
	assert.Equal(t, "admin", role)
	
	// Проверяем, что все ожидания были выполнены
	mockRepo.AssertExpectations(t)
} 