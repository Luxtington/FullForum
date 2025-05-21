package middleware

import (
	"AuthService/internal/models"
	"AuthService/internal/service"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockAuthService struct {
	mock.Mock
	ValidateTokenFunc func(token string) (*models.User, error)
}

func (m *mockAuthService) Register(username, email, password string) (*models.User, string, error) {
	args := m.Called(username, email, password)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*models.User), args.String(1), args.Error(2)
}

func (m *mockAuthService) Login(username, password string) (*models.User, string, error) {
	return nil, "", nil
}

func (m *mockAuthService) ValidateToken(token string) (*models.User, error) {
	return m.ValidateTokenFunc(token)
}

var _ service.IAuthService = (*mockAuthService)(nil)

func TestRequireAuth_Success(t *testing.T) {
	mockService := &mockAuthService{
		ValidateTokenFunc: func(token string) (*models.User, error) {
			return &models.User{
				ID:       1,
				Username: "testuser",
				Role:     "user",
			}, nil
		},
	}

	middleware := &AuthMiddleware{
		authService: mockService,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value("user").(*models.User)
		assert.True(t, ok)
		assert.Equal(t, "testuser", user.Username)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "valid-token")
	w := httptest.NewRecorder()

	handler := middleware.RequireAuth(nextHandler)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAuth_NoToken(t *testing.T) {
	mockService := &mockAuthService{}
	middleware := &AuthMiddleware{
		authService: mockService,
	}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler := middleware.RequireAuth(nextHandler)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "требуется аутентификация")
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	mockService := &mockAuthService{
		ValidateTokenFunc: func(token string) (*models.User, error) {
			return nil, service.ErrInvalidToken
		},
	}
	middleware := &AuthMiddleware{
		authService: mockService,
	}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "invalid-token")
	w := httptest.NewRecorder()

	handler := middleware.RequireAuth(nextHandler)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "недействительный токен")
} 