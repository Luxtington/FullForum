package service

import (
	"AuthService/internal/models"
	"AuthService/internal/repository"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrUserNotFound      = errors.New("пользователь не найден")
	ErrInvalidPassword   = errors.New("неверный пароль")
	ErrUserAlreadyExists = errors.New("пользователь уже существует")
	ErrInvalidToken      = errors.New("недействительный токен")
)

type AuthService struct {
	userRepo repository.UserRepository
	jwtKey   []byte
}

func NewAuthService(userRepo repository.UserRepository) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		jwtKey:   []byte("your-secret-key"), // В продакшене использовать безопасный ключ
	}
}

func (s *AuthService) Register(username, password string) (*models.User, string, error) {
	// Проверяем, существует ли пользователь
	exists, err := s.userRepo.UserExists(username)
	if err != nil {
		return nil, "", err
	}
	if exists {
		return nil, "", ErrUserAlreadyExists
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	// Создаем пользователя
	user := &models.User{
		Username: username,
		Password: string(hashedPassword),
		Role:     "user", // По умолчанию обычный пользователь
	}

	if err := s.userRepo.CreateUser(user); err != nil {
		return nil, "", err
	}

	// Генерируем JWT токен
	token, err := s.generateToken(user)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *AuthService) Login(username, password string) (*models.User, string, error) {
	// Получаем пользователя
	user, err := s.userRepo.GetUserByUsername(username)
	if err != nil {
		return nil, "", ErrUserNotFound
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, "", ErrInvalidPassword
	}

	// Генерируем JWT токен
	token, err := s.generateToken(user)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*models.User, error) {
	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.jwtKey, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Получаем ID пользователя из токена
		userID := uint(claims["user_id"].(float64))

		// Получаем пользователя из базы данных
		user, err := s.userRepo.GetUserByID(int(userID))
		if err != nil {
			return nil, ErrUserNotFound
		}

		return user, nil
	}

	return nil, ErrInvalidToken
}

func (s *AuthService) generateToken(user *models.User) (string, error) {
	// Создаем claims для токена
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Токен действителен 24 часа
	}

	// Создаем токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен
	tokenString, err := token.SignedString(s.jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
} 