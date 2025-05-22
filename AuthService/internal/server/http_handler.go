package server

import (
	_"AuthService/internal/models"
	"AuthService/internal/service"
	"AuthService/internal/errors"
	_"encoding/json"
	"net/http"
	_"strconv"
	"strings"
	_"time"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	service service.IAuthService
}

func NewAuthHandler(service service.IAuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.NewValidationError("Неверный формат данных", err))
		return
	}

	user, token, err := h.service.Register(req.Username, req.Email, req.Password)
	if err != nil {
		if err == service.ErrUserAlreadyExists {
			c.Error(errors.NewConflictError("Пользователь уже существует", err))
			return
		}
		c.Error(errors.NewInternalServerError("Ошибка при регистрации", err))
		return
	}

	c.SetCookie("auth_token", token, 3600*24, "/", "", false, false)

	c.JSON(http.StatusCreated, AuthResponse{
		UserID:   user.ID,
		Username: user.Username,
		Token:    token,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.NewValidationError("Неверный формат данных", err))
		return
	}

	user, token, err := h.service.Login(req.Username, req.Password)
	if err != nil {
		if err == service.ErrUserNotFound || err == service.ErrInvalidPassword {
			c.Error(errors.NewUnauthorizedError("Неверное имя пользователя или пароль", err))
			return
		}
		c.Error(errors.NewInternalServerError("Ошибка при входе", err))
		return
	}

	c.SetCookie("auth_token", token, 3600*24, "/", "", false, false)

	c.JSON(http.StatusOK, AuthResponse{
		UserID:   user.ID,
		Username: user.Username,
		Token:    token,
	})
}

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

	user, err := h.service.ValidateToken(token)
	if err != nil {
		c.Error(errors.NewUnauthorizedError("Недействительный токен", err))
		return
	}

	c.JSON(http.StatusOK, user)
}

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
	c.JSON(http.StatusOK, gin.H{"message": "успешный выход"})
} 