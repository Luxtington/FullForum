package main

import (
	"AuthService/internal/repository"
	"AuthService/internal/server"
	"AuthService/internal/service"
	"database/sql"
	_"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"log"
)

func main() {
	// Подключение к базе данных
	dsn := "host=localhost user=postgres password=postgres dbname=forum port=5432 sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Проверка подключения
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Инициализация репозитория
	userRepo := repository.NewUserRepository(db)

	// Инициализация сервиса
	authService := service.NewAuthService(userRepo)

	// Запуск gRPC сервера в отдельной горутине
	go func() {
		if err := server.StartGRPCServer(authService, "50051"); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	// Создание экземпляра Gin
	r := gin.Default()

	// Настройка CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// // Загрузка HTML шаблонов
	// r.LoadHTMLGlob("templates/*")
	// Настройка статических файлов
	r.Static("/static", "./static")

	// Инициализация обработчиков
	authHandler := server.NewAuthHandler(authService)

	// Маршруты для аутентификации
	r.POST("/api/auth/register", authHandler.Register)
	r.POST("/api/auth/login", authHandler.Login)

	// Запуск HTTP сервера
	log.Fatal(r.Run(":8082"))
} 