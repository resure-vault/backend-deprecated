package config

import (
    "os"
    "strconv"
    "log"

    "github.com/joho/godotenv"
)

type Config struct {
    Database DatabaseConfig
    JWT      JWTConfig
    Server   ServerConfig
    Redis    RedisConfig
}

type DatabaseConfig struct {
    Host     string
    Port     string
    User     string
    Password string
    DBName   string
    SSLMode  string
    Schema   string
}

type JWTConfig struct {
    Secret string
}

type ServerConfig struct {
    Port string
}

type RedisConfig struct {
    URL      string
    Host     string
    Port     string
    Password string
    DB       int
}

func Load() *Config {
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found: %v", err)
    }

    redisDB := 0
    if val := os.Getenv("REDIS_DB"); val != "" {
        if parsed, err := strconv.Atoi(val); err == nil {
            redisDB = parsed
        }
    }

    return &Config{
        Database: DatabaseConfig{
            Host:     getEnv("PROD_DB_HOST", ""),
            Port:     getEnv("PROD_DB_PORT", ""),
            User:     getEnv("PROD_DB_USER", ""),
            Password: getEnv("PROD_DB_PASSWORD", ""),
            DBName:   getEnv("PROD_DB_NAME", ""),
            SSLMode:  getEnv("DB_SSL_MODE", "disable"),
            Schema:   getEnv("PROD_DB_SCHEMA", "public"),
        },
        JWT: JWTConfig{
            Secret: getEnv("JWT_SECRET", ""),
        },
        Server: ServerConfig{
            Port: getEnv("PORT", "8080"),
        },
        Redis: RedisConfig{
            URL:      getEnv("REDIS_URL", ""),
            Host:     getEnv("REDIS_HOST", "localhost"),
            Port:     getEnv("REDIS_PORT", "6379"),
            Password: getEnv("REDIS_PASSWORD", ""),
            DB:       redisDB,
        },
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
