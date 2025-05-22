package handler

import (
    "AuthService/internal/models"
    "AuthService/internal/service"
    "AuthService/internal/errors"
    "github.com/gin-gonic/gin"
    "github.com/Luxtington/Shared/logger"
    "go.uber.org/zap"
    "strings"
    "time"
    _ "github.com/swaggo/swag"
    _ "github.com/swaggo/gin-swagger"
    _ "github.com/swaggo/files"
)

type AuthHandler struct {
    authService service.IAuthService
}

func NewAuthHandler(authService service.IAuthService) *AuthHandler {
    return &AuthHandler{
        authService: authService,
    }
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with username, email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param input body object true "Registration data"
// @Success 200 {object} models.SwaggerResponse "Returns user data, token and redirect URL"
// @Failure 400 {object} models.SwaggerResponse "error: Bad request or invalid data format"
// @Failure 400 {object} models.SwaggerResponse "error: Registration error message"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
    var req models.RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.Error(errors.NewValidationError("Неверный формат данных", err))
        return
    }

    user, token, err := h.authService.Register(req.Username, req.Email, req.Password)
    if err != nil {
        switch err.Error() {
        case service.ErrUserAlreadyExists.Error():
            c.Error(errors.NewConflictError("Пользователь уже существует", err))
        default:
            c.Error(errors.NewInternalServerError("Ошибка при регистрации", err))
        }
        return
    }
    
    c.SetCookie(
        "auth_token",
        token,
        int(time.Hour*24*7),
        "/",
        "localhost", 
        false, 
        false, 
    )
    
    c.JSON(200, gin.H{
        "user": user,
        "redirect_url": "http://localhost:8081",
        "token": token,
    })
}

// Login godoc
// @Summary User login
// @Description Authenticate user with username and password
// @Tags auth
// @Accept json
// @Produce json
// @Param input body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.SwaggerResponse "Returns user data, token and redirect URL"
// @Failure 400 {object} models.SwaggerResponse "error: Bad request or invalid data format"
// @Failure 401 {object} models.SwaggerResponse "error: Authentication failed"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
    var req models.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.Error(errors.NewValidationError("Неверный формат данных", err))
        return
    }

    user, token, err := h.authService.Login(req.Username, req.Password)
    if err != nil {
        switch err.Error() {
        case service.ErrUserNotFound.Error(), service.ErrInvalidPassword.Error():
            c.Error(errors.NewUnauthorizedError("Неверное имя пользователя или пароль", err))
        default:
            c.Error(errors.NewInternalServerError("Ошибка при входе", err))
        }
        return
    }
    
    c.SetCookie(
        "auth_token",
        token,
        int(time.Hour*24*7), 
        "/",
        "localhost",  
        false, 
        false,  
    )
    
    c.JSON(200, gin.H{
        "user": user,
        "token": token,
        "redirect_url": "http://localhost:8081",
    })
}

// ValidateToken godoc
// @Summary Validate JWT token
// @Description Validate the JWT token from Authorization header or cookie
// @Tags auth
// @Produce json
// @Security ApiKeyAuth
// @Param Authorization header string false "Bearer token"
// @Success 200 {object} models.User "Returns authenticated user data"
// @Failure 401 {object} models.SwaggerResponse "error: Token not provided or invalid"
// @Router /auth/validate [get]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
    authHeader := c.GetHeader("Authorization")
    var token string
    if authHeader != "" {
        token = strings.TrimPrefix(authHeader, "Bearer ")
    } else {
        var err error
        token, err = c.Cookie("auth_token")
        if err != nil {
            c.Error(errors.NewUnauthorizedError("Токен не предоставлен", err))
            return
        }
    }

    if token == "" {
        c.Error(errors.NewUnauthorizedError("Токен не предоставлен", nil))
        return
    }

    user, err := h.authService.ValidateToken(token)
    if err != nil {
        c.Error(errors.NewUnauthorizedError("Недействительный токен", err))
        return
    }

    log := logger.GetLogger()
    log.Info("User role in ValidateToken handler", zap.String("role", user.Role))
    c.JSON(200, user)
}

// Logout godoc
// @Summary User logout
// @Description Clear authentication cookie
// @Tags auth
// @Produce json
// @Success 200 {object} models.SwaggerResponse "message: Logout success message"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
    c.SetCookie(
        "auth_token",
        "",
        -1,
        "/",
        "",
        false,
        true,
    )
    c.JSON(200, gin.H{"message": "успешный выход"})
} 