package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func setupRouter(handler *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)
	return r
}

func TestRegister_Success(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Ожидаем, что пользователь не существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем создание пользователя
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), "user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var response AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response.Username)
	assert.NotEmpty(t, response.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_InvalidData(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(`{"invalid": "data"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_UserExists(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Ожидаем, что пользователь существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "уже существует")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_DBError(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Ожидаем, что пользователь не существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем ошибку при создании пользователя
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), "user").
		WillReturnError(sqlmock.ErrCancelled)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "ошибка при регистрации")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_Success(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Генерируем правильный хеш пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response AuthResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response.Username)
	assert.NotEmpty(t, response.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_InvalidData(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(`{"invalid": "data"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_UserNotFound(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Ожидаем, что пользователь не найден
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "nonexistent", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "неверное имя пользователя или пароль")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_InvalidPassword(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Генерируем хеш для другого пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("wrongpassword"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "неверное имя пользователя или пароль")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_Success_Cookie(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Генерируем правильный хеш пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(`{"username": "testuser", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	// Проверяем установку cookie
	cookies := w.Result().Cookies()
	var authCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			authCookie = cookie
			break
		}
	}
	assert.NotNil(t, authCookie)
	assert.Equal(t, "auth_token", authCookie.Name)
	assert.NotEmpty(t, authCookie.Value)
	assert.Equal(t, 3600*24, authCookie.MaxAge)
	assert.Equal(t, "/", authCookie.Path)
	assert.False(t, authCookie.Secure)
	assert.False(t, authCookie.HttpOnly)
	
	var response AuthResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response.Username)
	assert.NotEmpty(t, response.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_Success_Cookie(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	handler := NewAuthHandler(authService)
	router := setupRouter(handler)

	// Ожидаем, что пользователь не существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем создание пользователя
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), "user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(`{"username": "testuser", "email": "test@example.com", "password": "password123"}`))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	
	// Проверяем установку cookie
	cookies := w.Result().Cookies()
	var authCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			authCookie = cookie
			break
		}
	}
	assert.NotNil(t, authCookie)
	assert.Equal(t, "auth_token", authCookie.Name)
	assert.NotEmpty(t, authCookie.Value)
	assert.Equal(t, 3600*24, authCookie.MaxAge)
	assert.Equal(t, "/", authCookie.Path)
	assert.False(t, authCookie.Secure)
	assert.False(t, authCookie.HttpOnly)
	
	var response AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response.Username)
	assert.NotEmpty(t, response.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
} 