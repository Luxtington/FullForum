package handler

import (
    "AuthService/internal/models"
    "AuthService/internal/service"
    "github.com/gin-gonic/gin"
    "strings"
    "time"
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
    
    // Устанавливаем куки с токеном
    c.SetCookie(
        "auth_token",
        response.Token,
        int(time.Hour*24*7), // 7 дней
        "/",
        "localhost",  // Устанавливаем домен localhost
        false, // httpOnly
        false,  // secure
    )
    
    c.JSON(200, gin.H{
        "user": response.User,
        "redirect_url": "http://localhost:8081",
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
    
    // Устанавливаем куки с токеном
    c.SetCookie(
        "auth_token",
        response.Token,
        int(time.Hour*24*7), // 7 дней
        "/",
        "localhost",  // Устанавливаем домен localhost
        false, // httpOnly
        false,  // secure
    )
    
    c.JSON(200, gin.H{
        "user": response.User,
        "token": response.Token,
        "redirect_url": "http://localhost:8081",
    })
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
    // Сначала проверяем заголовок Authorization
    authHeader := c.GetHeader("Authorization")
    var token string
    if authHeader != "" {
        // Убираем префикс "Bearer " если он есть
        token = strings.TrimPrefix(authHeader, "Bearer ")
    } else {
        // Если нет в заголовке, проверяем куки
        var err error
        token, err = c.Cookie("auth_token")
        if err != nil {
            c.JSON(401, gin.H{"error": "токен не предоставлен"})
            return
        }
    }

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