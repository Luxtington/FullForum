package models

import "time"

type User struct {
    ID        uint       `json:"id"`
    Username  string     `json:"username"`
    Email     string     `json:"email"`
    Password  string     `json:"-"`
    Role      string     `json:"role"`
    CreatedAt time.Time  `json:"created_at"`
    UpdatedAt time.Time  `json:"updated_at"`
    DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type RegisterRequest struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type AuthResponse struct {
    Token string `json:"token"`
    User  User   `json:"user"`
} 