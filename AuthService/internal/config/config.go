package config

import (
    "fmt"
    "gopkg.in/yaml.v2"
    "os"
    "time"
)

type Config struct {
    Server   ServerConfig   `yaml:"server"`
    Database DatabaseConfig `yaml:"database"`
    JWT      JWTConfig     `yaml:"jwt"`
}

type ServerConfig struct {
    Port int    `yaml:"port"`
    Host string `yaml:"host"`
}

type DatabaseConfig struct {
    Host            string        `yaml:"host"`
    Port            int           `yaml:"port"`
    User            string        `yaml:"user"`
    Password        string        `yaml:"password"`
    DBName          string        `yaml:"dbname"`
    SSLMode         string        `yaml:"sslmode"`
    MaxOpenConns    int           `yaml:"max_open_conns"`
    MaxIdleConns    int           `yaml:"max_idle_conns"`
    ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type JWTConfig struct {
    SecretKey     string        `yaml:"secret_key"`
    TokenLifetime time.Duration `yaml:"token_lifetime"`
}

func (d *DatabaseConfig) GetDSN() string {
    return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

func LoadConfig(path string) (*Config, error) {
    file, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("ошибка чтения файла конфигурации: %w", err)
    }

    var config Config
    if err := yaml.Unmarshal(file, &config); err != nil {
        return nil, fmt.Errorf("ошибка разбора файла конфигурации: %w", err)
    }

    return &config, nil
} 