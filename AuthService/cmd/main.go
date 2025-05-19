package main

import (
	"AuthService/internal/repository"
	"AuthService/internal/server"
	"AuthService/internal/service"
	"database/sql"
	_"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/Luxtington/Shared/logger"
	"go.uber.org/zap"
	"net/http"
)

func main() {
	logger.InitLogger()
	log := logger.GetLogger()

	// Подключение к базе данных
	dsn := "host=localhost user=postgres password=postgres dbname=forum port=5432 sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Проверка подключения
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database", zap.Error(err))
	}

	// Инициализация репозитория
	userRepo := repository.NewUserRepository(db)

	// Инициализация сервиса
	authService := service.NewAuthService(userRepo)

	// Запуск gRPC сервера в отдельной горутине
	go func() {
		if err := server.StartGRPCServer(authService, "50051"); err != nil {
			log.Fatal("Failed to start gRPC server", zap.Error(err))
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

	// Загрузка HTML шаблонов
	r.LoadHTMLGlob("internal/templates/*")
	// Настройка статических файлов
	r.Static("/static", "./static")

	// Инициализация обработчиков
	authHandler := server.NewAuthHandler(authService)

	// Маршруты для аутентификации
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	// Маршруты для аутентификации
	r.POST("/api/auth/register", authHandler.Register)
	r.POST("/api/auth/login", authHandler.Login)

	// Запуск HTTP сервера
	if err := r.Run(":8082"); err != nil {
		log.Fatal("Failed to start HTTP server", zap.Error(err))
	}
} 