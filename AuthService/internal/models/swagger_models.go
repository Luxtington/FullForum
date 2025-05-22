package models

// SwaggerResponse представляет общий формат ответа API
type SwaggerResponse struct {
    User        *User  `json:"user,omitempty"`
    Token       string `json:"token,omitempty"`
    RedirectURL string `json:"redirect_url,omitempty"`
    Error       string `json:"error,omitempty"`
    Message     string `json:"message,omitempty"`
} 