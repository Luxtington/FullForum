package service

import (
    "AuthService/internal/models"
    "AuthService/internal/repository"
    "errors"
    "golang.org/x/crypto/bcrypt"
    "github.com/golang-jwt/jwt"
    "time"
)

type AuthService interface {
    Register(req *models.RegisterRequest) (*models.AuthResponse, error)
    Login(req *models.LoginRequest) (*models.AuthResponse, error)
    ValidateToken(token string) (*models.User, error)
}

type authService struct {
    userRepo repository.UserRepository
    jwtKey   []byte
}

func NewAuthService(userRepo repository.UserRepository, jwtKey string) AuthService {
    return &authService{
        userRepo: userRepo,
        jwtKey:   []byte(jwtKey),
    }
}

func (s *authService) Register(req *models.RegisterRequest) (*models.AuthResponse, error) {
    // Проверяем, существует ли пользователь с таким email
    existingUser, err := s.userRepo.GetByEmail(req.Email)
    if err != nil {
        return nil, err
    }
    if existingUser != nil {
        return nil, errors.New("пользователь с таким email уже существует")
    }

    // Проверяем, существует ли пользователь с таким username
    existingUser, err = s.userRepo.GetByUsername(req.Username)
    if err != nil {
        return nil, err
    }
    if existingUser != nil {
        return nil, errors.New("пользователь с таким именем уже существует")
    }

    // Создаем нового пользователя
    user := &models.User{
        Username:     req.Username,
        Email:        req.Email,
        PasswordHash: req.Password,
    }

    if err := s.userRepo.Create(user); err != nil {
        return nil, err
    }

    // Генерируем JWT токен
    token, err := s.generateToken(user)
    if err != nil {
        return nil, err
    }

    return &models.AuthResponse{
        Token: token,
        User:  *user,
    }, nil
}

func (s *authService) Login(req *models.LoginRequest) (*models.AuthResponse, error) {
    user, err := s.userRepo.GetByUsername(req.Username)
    if err != nil {
        return nil, err
    }
    if user == nil {
        return nil, errors.New("неверное имя пользователя или пароль")
    }

    // Проверяем пароль
    err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
    if err != nil {
        return nil, errors.New("неверное имя пользователя или пароль")
    }

    // Генерируем JWT токен
    token, err := s.generateToken(user)
    if err != nil {
        return nil, err
    }

    return &models.AuthResponse{
        Token: token,
        User:  *user,
    }, nil
}

func (s *authService) ValidateToken(tokenString string) (*models.User, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return s.jwtKey, nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        userID := int(claims["user_id"].(float64))
        return s.userRepo.GetByID(userID)
    }

    return nil, errors.New("недействительный токен")
}

func (s *authService) generateToken(user *models.User) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id":  user.ID,
        "username": user.Username,
        "exp":      time.Now().Add(time.Hour * 24 * 7).Unix(), // Токен действителен 7 дней
    })

    return token.SignedString(s.jwtKey)
} 