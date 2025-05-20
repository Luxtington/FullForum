package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseConfig_GetDSN(t *testing.T) {
	config := &DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		DBName:   "testdb",
		SSLMode:  "disable",
	}

	expected := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
	assert.Equal(t, expected, config.GetDSN())
}

func TestLoadConfig_Success(t *testing.T) {
	// Создаем временный конфиг файл
	configContent := `
server:
  port: 8080
  host: localhost
database:
  host: localhost
  port: 5432
  user: testuser
  password: testpass
  dbname: testdb
  sslmode: disable
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_lifetime: 1h
jwt:
  secret_key: testkey
  token_lifetime: 24h
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(configContent))
	assert.NoError(t, err)
	tmpFile.Close()

	// Загружаем конфиг
	config, err := LoadConfig(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Проверяем значения
	assert.Equal(t, 8080, config.Server.Port)
	assert.Equal(t, "localhost", config.Server.Host)
	assert.Equal(t, "localhost", config.Database.Host)
	assert.Equal(t, 5432, config.Database.Port)
	assert.Equal(t, "testuser", config.Database.User)
	assert.Equal(t, "testpass", config.Database.Password)
	assert.Equal(t, "testdb", config.Database.DBName)
	assert.Equal(t, "disable", config.Database.SSLMode)
	assert.Equal(t, 10, config.Database.MaxOpenConns)
	assert.Equal(t, 5, config.Database.MaxIdleConns)
	assert.Equal(t, time.Hour, config.Database.ConnMaxLifetime)
	assert.Equal(t, "testkey", config.JWT.SecretKey)
	assert.Equal(t, 24*time.Hour, config.JWT.TokenLifetime)
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("nonexistent.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ошибка чтения файла конфигурации")
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// Создаем временный файл с неверным YAML
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte("invalid: yaml: content: [}"))
	assert.NoError(t, err)
	tmpFile.Close()

	// Пытаемся загрузить конфиг
	_, err = LoadConfig(tmpFile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ошибка разбора файла конфигурации")
} 