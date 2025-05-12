package main

import (
    "AuthService/internal/config"
    "AuthService/internal/handler"
    "AuthService/internal/repository"
    "AuthService/internal/service"
    "database/sql"
    "fmt"
    "log"
    _ "github.com/lib/pq"
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/cors"
)

func main() {
    // Загрузка конфигурации
    cfg, err := config.LoadConfig("config/config.yaml")
    if err != nil {
        log.Fatalf("Ошибка загрузки конфигурации: %v", err)
    }

    // Подключение к базе данных
    db, err := sql.Open("postgres", cfg.Database.GetDSN())
    if err != nil {
        log.Fatalf("Ошибка подключения к базе данных: %v", err)
    }
    defer db.Close()

    // Настройка пула соединений
    db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
    db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
    db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

    // Проверка подключения
    if err := db.Ping(); err != nil {
        log.Fatalf("Ошибка проверки подключения к базе данных: %v", err)
    }

    // Инициализация репозитория
    userRepo := repository.NewUserRepository(db)

    // Инициализация сервиса
    authService := service.NewAuthService(userRepo, cfg.JWT.SecretKey)

    // Инициализация обработчиков
    authHandler := handler.NewAuthHandler(authService)
    templateHandler := handler.NewTemplateHandler("internal/templates")

    // Создаём gin router
    r := gin.Default()

    // Настройка CORS
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"*"},
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
    }))

    // Настройка статических файлов
    r.Static("/static", "./internal/templates")

    // API маршруты
    r.POST("/api/auth/register", authHandler.RegisterGin)
    r.POST("/api/auth/login", authHandler.LoginGin)
    r.GET("/api/auth/validate", authHandler.ValidateTokenGin)

    // Маршруты для страниц (если нужно)
    r.GET("/register", templateHandler.ServeRegisterPageGin)
    r.GET("/login", templateHandler.ServeLoginPageGin)

    // Запуск сервера
    serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
    log.Printf("Сервер аутентификации запущен на %s", serverAddr)
    log.Fatal(r.Run(serverAddr))
} 