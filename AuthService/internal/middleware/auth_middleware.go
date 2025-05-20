package middleware

import (
    "AuthService/internal/service"
    "net/http"
    "context"
)

type AuthMiddleware struct {
    authService service.IAuthService
}

func NewAuthMiddleware(authService service.IAuthService) *AuthMiddleware {
    return &AuthMiddleware{
        authService: authService,
    }
}

func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" {
            http.Error(w, "требуется аутентификация", http.StatusUnauthorized)
            return
        }

        user, err := m.authService.ValidateToken(token)
        if err != nil {
            http.Error(w, "недействительный токен", http.StatusUnauthorized)
            return
        }

        // Добавляем информацию о пользователе в контекст запроса
        ctx := r.Context()
        ctx = context.WithValue(ctx, "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
} 