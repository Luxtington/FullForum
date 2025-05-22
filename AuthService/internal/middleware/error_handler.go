package middleware

import (
	"AuthService/internal/errors"
	"github.com/gin-gonic/gin"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			if authErr, ok := err.(*errors.AuthError); ok {
				c.JSON(authErr.Code, gin.H{
					"error": authErr.Message,
				})
				return
			}

			// Если ошибка не является AuthError, возвращаем 500
			c.JSON(500, gin.H{
				"error": "внутренняя ошибка сервера",
			})
		}
	}
} 