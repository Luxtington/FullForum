package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"AuthService/internal/models"
	"AuthService/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(username, password string) (*models.User, string, error) {
	args := m.Called(username, password)
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

func setupRouter(handler *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)
	r.GET("/validate", handler.ValidateToken)
	r.POST("/logout", handler.Logout)
	return r
}

func TestRegister_Success(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}
	expectedToken := "test-token"

	mockService.On("Register", "testuser", "password123").Return(expectedUser, expectedToken, nil)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))

	// Выполнение запроса
	handler.Register(c)

	// Проверки
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	user := response["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "testuser", user["username"])
	assert.Equal(t, "test@example.com", user["email"])
	assert.Equal(t, "http://localhost:8081", response["redirect_url"])

	// Проверка куки
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "auth_token", cookies[0].Name)
	assert.Equal(t, expectedToken, cookies[0].Value)
}

func TestRegister_InvalidData(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"invalid": "data"}`))

	// Выполнение запроса
	handler.Register(c)

	// Проверки
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "неверный формат данных", response["error"])
}

func TestRegister_Error(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	mockService.On("Register", "testuser", "password123").Return(nil, "", assert.AnError)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))

	// Выполнение запроса
	handler.Register(c)

	// Проверки
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, assert.AnError.Error(), response["error"])
}

func TestLogin_Success(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}
	expectedToken := "test-token"

	mockService.On("Login", "testuser", "password123").Return(expectedUser, expectedToken, nil)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))

	// Выполнение запроса
	handler.Login(c)

	// Проверки
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	user := response["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "testuser", user["username"])
	assert.Equal(t, "test@example.com", user["email"])
	assert.Equal(t, expectedToken, response["token"])
	assert.Equal(t, "http://localhost:8081", response["redirect_url"])

	// Проверка куки
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "auth_token", cookies[0].Name)
	assert.Equal(t, expectedToken, cookies[0].Value)
}

func TestLogin_InvalidData(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"invalid": "data"}`))

	// Выполнение запроса
	handler.Login(c)

	// Проверки
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "неверный формат данных", response["error"])
}

func TestLogin_Error(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	mockService.On("Login", "testuser", "password123").Return(nil, "", assert.AnError)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))

	// Выполнение запроса
	handler.Login(c)

	// Проверки
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, assert.AnError.Error(), response["error"])
}

func TestValidateToken_Success(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	mockService.On("ValidateToken", "test-token").Return(expectedUser, nil)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/validate", nil)
	c.Request.Header.Set("Authorization", "Bearer test-token")

	// Выполнение запроса
	handler.ValidateToken(c)

	// Проверки
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, float64(1), response["id"])
	assert.Equal(t, "testuser", response["username"])
	assert.Equal(t, "test@example.com", response["email"])
}

func TestValidateToken_NoToken(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/validate", nil)

	// Выполнение запроса
	handler.ValidateToken(c)

	// Проверки
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "токен не предоставлен", response["error"])
}

func TestValidateToken_InvalidToken(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	mockService.On("ValidateToken", "invalid-token").Return(nil, assert.AnError)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/validate", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid-token")

	// Выполнение запроса
	handler.ValidateToken(c)

	// Проверки
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, assert.AnError.Error(), response["error"])
}

func TestLogout_Success(t *testing.T) {
	// Настройка
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	// Создание тестового запроса
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/logout", nil)

	// Выполнение запроса
	handler.Logout(c)

	// Проверки
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "успешный выход", response["message"])

	// Проверка куки
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "auth_token", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
} 