package main

import (
    "AuthService/internal/config"
    "AuthService/internal/handler"
    "AuthService/internal/repository"
    "AuthService/internal/service"
    "database/sql"
    "fmt"
    "log"
    "net/http"
    _ "github.com/lib/pq"
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

    // Настройка маршрутов API
    http.HandleFunc("/api/auth/register", authHandler.Register)
    http.HandleFunc("/api/auth/login", authHandler.Login)
    http.HandleFunc("/api/auth/validate", authHandler.ValidateToken)

    // Настройка маршрутов для страниц
    http.HandleFunc("/register", templateHandler.ServeRegisterPage)
    http.HandleFunc("/login", templateHandler.ServeLoginPage)

    // Запуск сервера
    serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
    log.Printf("Сервер аутентификации запущен на %s", serverAddr)
    log.Fatal(http.ListenAndServe(serverAddr, nil))
} 