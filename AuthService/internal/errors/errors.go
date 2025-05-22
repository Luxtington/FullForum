package errors

import "fmt"

type AuthError struct {
	Code    int
	Message string
	Err     error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Константы для типов ошибок
const (
	ErrInvalidCredentials = "invalid credentials error"
	ErrUserNotFound      = "user not found error"
	ErrUserExists        = "user is already exist error"
	ErrInvalidToken      = "invalid token error"
	ErrInvalidData       = "invalid data error"
	ErrInternalServer    = "internal server error"
)

// Конструкторы ошибок
func NewValidationError(message string, err error) *AuthError {
	return &AuthError{
		Code:    400,
		Message: message,
		Err:     err,
	}
}

func NewUnauthorizedError(message string, err error) *AuthError {
	return &AuthError{
		Code:    401,
		Message: message,
		Err:     err,
	}
}

func NewForbiddenError(message string, err error) *AuthError {
	return &AuthError{
		Code:    403,
		Message: message,
		Err:     err,
	}
}

func NewNotFoundError(message string, err error) *AuthError {
	return &AuthError{
		Code:    404,
		Message: message,
		Err:     err,
	}
}

func NewConflictError(message string, err error) *AuthError {
	return &AuthError{
		Code:    409,
		Message: message,
		Err:     err,
	}
}

func NewInternalServerError(message string, err error) *AuthError {
	return &AuthError{
		Code:    500,
		Message: message,
		Err:     err,
	}
} 