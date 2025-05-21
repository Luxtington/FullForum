package server

import (
	"AuthService/proto"
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/dgrijalva/jwt-go"
)

func TestNewGRPCServer(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)
	assert.NotNil(t, server)
	assert.Equal(t, authService, server.authService)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_ValidateToken(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	resp, err := server.ValidateToken(context.Background(), &proto.ValidateTokenRequest{Token: "invalid-token"})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_ValidateToken_Error(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Не ожидаем никаких запросов к БД, так как токен невалидный и запрос к БД не дойдет
	resp, err := server.ValidateToken(context.Background(), &proto.ValidateTokenRequest{Token: "invalid-token"})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_ValidateToken_DBError(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Создаем валидный токен с правильной подписью
	claims := jwt.MapClaims{
		"user_id":  1,
		"username": "testuser",
		"role":     "user",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("your-secret-key"))
	require.NoError(t, err)

	// Ожидаем ошибку при поиске пользователя по ID
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs(1).
		WillReturnError(sqlmock.ErrCancelled)

	resp, err := server.ValidateToken(context.Background(), &proto.ValidateTokenRequest{Token: tokenString})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Register(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Ожидаем, что пользователь не существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем создание пользователя
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), "user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	resp, err := server.Register(context.Background(), &proto.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "testuser", resp.Username)
	assert.NotEmpty(t, resp.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Register_UserExists(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Ожидаем, что пользователь существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	resp, err := server.Register(context.Background(), &proto.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Register_DBError(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Ожидаем, что пользователь не существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем ошибку при создании пользователя
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), "user").
		WillReturnError(sqlmock.ErrCancelled)

	resp, err := server.Register(context.Background(), &proto.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Login(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Генерируем правильный хеш пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	resp, err := server.Login(context.Background(), &proto.LoginRequest{
		Username: "testuser",
		Password: "password123",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "testuser", resp.Username)
	assert.NotEmpty(t, resp.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Login_UserNotFound(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Ожидаем, что пользователь не найден
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}))

	resp, err := server.Login(context.Background(), &proto.LoginRequest{
		Username: "nonexistent",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGRPCServer_Login_InvalidPassword(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	server := NewGRPCServer(authService)

	// Генерируем хеш для другого пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("wrongpassword"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	resp, err := server.Login(context.Background(), &proto.LoginRequest{
		Username: "testuser",
		Password: "password123",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStartGRPCServer(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	// Запускаем сервер в отдельной горутине
	go func() {
		err := StartGRPCServer(authService, "50051")
		assert.NoError(t, err)
	}()

	// Даем серверу время на запуск
	time.Sleep(100 * time.Millisecond)

	// Подключаемся к серверу
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)
	defer conn.Close()

	// Создаем клиент
	client := proto.NewAuthServiceClient(conn)

	// Генерируем правильный хеш пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Ожидаем поиск пользователя
	mock.ExpectQuery("SELECT id, username, email, password, role").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "role"}).
			AddRow(1, "testuser", "test@example.com", string(hashedPassword), "user"))

	// Тестируем метод Login
	resp, err := client.Login(context.Background(), &proto.LoginRequest{
		Username: "testuser",
		Password: "password123",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "testuser", resp.Username)
	assert.NotEmpty(t, resp.Token)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStartGRPCServer_Error(t *testing.T) {
	db, mock, authService := setupTestDB(t)
	defer db.Close()

	// Пытаемся запустить сервер на недопустимом порту
	err := StartGRPCServer(authService, "invalid-port")
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
} 