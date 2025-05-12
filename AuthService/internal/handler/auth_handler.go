package handler

import (
    "AuthService/internal/models"
    "AuthService/internal/service"
    "github.com/gin-gonic/gin"
)

type AuthHandler struct {
    authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
    return &AuthHandler{
        authService: authService,
    }
}

func (h *AuthHandler) Register(c *gin.Context) {
    var req models.RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "неверный формат данных"})
        return
    }
    response, err := h.authService.Register(&req)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Возвращаем JSON с токеном и URL для перенаправления
    c.JSON(200, gin.H{
        "token": response.Token,
        "user": response.User,
        "redirect_url": "http://localhost:8080",
    })
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req models.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "неверный формат данных"})
        return
    }
    response, err := h.authService.Login(&req)
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }
    
    // Возвращаем JSON с токеном и URL для перенаправления
    c.JSON(200, gin.H{
        "token": response.Token,
        "user": response.User,
        "redirect_url": "http://localhost:8080",
    })
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
    token := c.GetHeader("Authorization")
    if token == "" {
        c.JSON(401, gin.H{"error": "токен не предоставлен"})
        return
    }
    user, err := h.authService.ValidateToken(token)
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, user)
} 