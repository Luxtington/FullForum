package server

import (
	"AuthService/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, token, err := h.authService.Register(req.Username, req.Email, req.Password)
	if err != nil {
		if err == service.ErrUserAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка при регистрации"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "неверный формат данных"})
		return
	}

	user, token, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		if err == service.ErrUserNotFound || err == service.ErrInvalidPassword {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "неверное имя пользователя или пароль"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ошибка при входе"})
		return
	}

	c.SetCookie("auth_token", token, 3600*24, "/", "", false, false)

	c.JSON(http.StatusOK, AuthResponse{
		UserID:   user.ID,
		Username: user.Username,
		Token:    token,
	})
} 