package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"AuthService/internal/models"
	"AuthService/internal/middleware"
	"AuthService/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter(handler *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	
	// Добавляем middleware для обработки ошибок
	r.Use(middleware.ErrorHandler())
	
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)
	r.GET("/validate", handler.ValidateToken)
	r.POST("/logout", handler.Logout)
	return r
}

func TestRegister_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}
	expectedToken := "test-token"

	mockService.On("Register", "testuser", "test@example.com", "password123").Return(expectedUser, expectedToken, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, float64(1), response["user_id"])
	assert.Equal(t, "testuser", response["username"])
	assert.Equal(t, expectedToken, response["token"])
}

func TestRegister_InvalidData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(`invalid json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Неверный формат данных", response["error"])
}

func TestRegister_UserExists(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	mockService.On("Register", "existinguser", "existing@example.com", "password123").Return(nil, "", service.ErrUserAlreadyExists)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "existinguser", "email": "existing@example.com", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Пользователь уже существует", response["error"])
}

func TestRegister_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	mockService.On("Register", "testuser", "test@example.com", "password123").Return(nil, "", assert.AnError)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Ошибка при регистрации", response["error"])
}

func TestLogin_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}
	expectedToken := "test-token"

	mockService.On("Login", "testuser", "password123").Return(expectedUser, expectedToken, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, float64(1), response["user_id"])
	assert.Equal(t, "testuser", response["username"])
	assert.Equal(t, expectedToken, response["token"])
}

func TestLogin_InvalidData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(`invalid json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Неверный формат данных", response["error"])
}

func TestLogin_UserNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	mockService.On("Login", "nonexistent", "password123").Return(nil, "", service.ErrUserNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "nonexistent", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Неверное имя пользователя или пароль", response["error"])
}

func TestLogin_InvalidPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	mockService.On("Login", "testuser", "password123").Return(nil, "", service.ErrInvalidPassword)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Неверное имя пользователя или пароль", response["error"])
}

func TestValidateToken_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	mockService.On("ValidateToken", "valid-token").Return(expectedUser, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/validate", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.User
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, uint(1), response.ID)
	assert.Equal(t, "testuser", response.Username)
}

func TestValidateToken_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/validate", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Токен не предоставлен", response["error"])
}

func TestValidateToken_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	mockService.On("ValidateToken", "invalid-token").Return(nil, service.ErrInvalidToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/validate", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Недействительный токен", response["error"])
}

func TestLogout_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/logout", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "успешный выход", response["message"])
} 