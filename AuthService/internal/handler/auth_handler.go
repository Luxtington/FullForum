package handler

import (
    "AuthService/internal/models"
    "AuthService/internal/service"
    "encoding/json"
    "net/http"
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

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    var req models.RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "неверный формат данных", http.StatusBadRequest)
        return
    }

    response, err := h.authService.Register(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    var req models.LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "неверный формат данных", http.StatusBadRequest)
        return
    }

    response, err := h.authService.Login(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    token := r.Header.Get("Authorization")
    if token == "" {
        http.Error(w, "токен не предоставлен", http.StatusUnauthorized)
        return
    }

    user, err := h.authService.ValidateToken(token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) RegisterGin(c *gin.Context) {
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
    c.JSON(200, response)
}

func (h *AuthHandler) LoginGin(c *gin.Context) {
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
    c.JSON(200, response)
}

func (h *AuthHandler) ValidateTokenGin(c *gin.Context) {
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