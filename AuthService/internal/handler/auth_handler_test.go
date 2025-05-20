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
)

type mockAuthService struct {
	RegisterFunc      func(username, password string) (*models.User, string, error)
	LoginFunc         func(username, password string) (*models.User, string, error)
	ValidateTokenFunc func(token string) (*models.User, error)
}

var _ service.IAuthService = (*mockAuthService)(nil)

func (m *mockAuthService) Register(username, password string) (*models.User, string, error) {
	return m.RegisterFunc(username, password)
}

func (m *mockAuthService) Login(username, password string) (*models.User, string, error) {
	return m.LoginFunc(username, password)
}

func (m *mockAuthService) ValidateToken(token string) (*models.User, error) {
	return m.ValidateTokenFunc(token)
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
	mockService := &mockAuthService{
		RegisterFunc: func(username, password string) (*models.User, string, error) {
			return &models.User{
				ID:       1,
				Username: username,
				Email:    "test@mail.com",
				Role:     "user",
			}, "token123", nil
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	body := models.RegisterRequest{
		Username: "test",
		Email:    "test@mail.com",
		Password: "1234",
	}
	jsonBody, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "test@mail.com")
	cookie := w.Header().Get("Set-Cookie")
	assert.Contains(t, cookie, "auth_token=token123")
}

func TestRegister_BadRequest(t *testing.T) {
	mockService := &mockAuthService{}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer([]byte("bad json")))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "неверный формат данных")
}

func TestRegister_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		RegisterFunc: func(username, password string) (*models.User, string, error) {
			return nil, "", errors.New("ошибка регистрации")
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	body := models.RegisterRequest{
		Username: "test",
		Email:    "test@mail.com",
		Password: "1234",
	}
	jsonBody, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "ошибка регистрации")
}

func TestLogin_Success(t *testing.T) {
	mockService := &mockAuthService{
		LoginFunc: func(username, password string) (*models.User, string, error) {
			return &models.User{
				ID:       2,
				Username: username,
				Email:    "user@mail.com",
				Role:     "user",
			}, "token456", nil
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	body := models.LoginRequest{
		Username: "user",
		Password: "pass",
	}
	jsonBody, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "token456")
	assert.Contains(t, w.Body.String(), "user@mail.com")
}

func TestLogin_BadRequest(t *testing.T) {
	mockService := &mockAuthService{}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte("bad json")))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "неверный формат данных")
}

func TestLogin_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		LoginFunc: func(username, password string) (*models.User, string, error) {
			return nil, "", errors.New("ошибка входа")
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	body := models.LoginRequest{
		Username: "user",
		Password: "pass",
	}
	jsonBody, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "ошибка входа")
}

func TestValidateToken_Header_Success(t *testing.T) {
	mockService := &mockAuthService{
		ValidateTokenFunc: func(token string) (*models.User, error) {
			return &models.User{
				ID:       3,
				Username: "tokuser",
				Email:    "tok@mail.com",
				Role:     "admin",
			}, nil
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/validate", nil)
	req.Header.Set("Authorization", "Bearer testtoken")

	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "tokuser")
	assert.Contains(t, w.Body.String(), "admin")
}

func TestValidateToken_Cookie_Success(t *testing.T) {
	mockService := &mockAuthService{
		ValidateTokenFunc: func(token string) (*models.User, error) {
			return &models.User{
				ID:       4,
				Username: "cookieuser",
				Email:    "cookie@mail.com",
				Role:     "user",
			}, nil
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/validate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookietoken"})

	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "cookieuser")
	assert.Contains(t, w.Body.String(), "user")
}

func TestValidateToken_NoToken(t *testing.T) {
	mockService := &mockAuthService{}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/validate", nil)

	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "токен не предоставлен")
}

func TestValidateToken_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		ValidateTokenFunc: func(token string) (*models.User, error) {
			return nil, errors.New("недействительный токен")
		},
	}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/validate", nil)
	req.Header.Set("Authorization", "Bearer badtoken")

	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "недействительный токен")
}

func TestLogout(t *testing.T) {
	mockService := &mockAuthService{}
	h := NewAuthHandler(mockService)
	r := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/logout", nil)

	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "успешный выход")
} 