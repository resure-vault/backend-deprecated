package database

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/redis/go-redis/v9"
    "secrets-vault-backend/internal/config"
)

var (
    Client *redis.Client
    ctx    = context.Background()
)

func InitializeRedis(cfg *config.Config) {
    if cfg.Redis.URL != "" {
        opt, err := redis.ParseURL(cfg.Redis.URL)
        if err != nil {
            log.Fatalf("Failed to parse Redis URL: %v", err)
        }
        Client = redis.NewClient(opt)
    } else {
        Client = redis.NewClient(&redis.Options{
            Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
            Password:     cfg.Redis.Password,
            DB:           cfg.Redis.DB,
            MaxRetries:   3,
            DialTimeout:  5 * time.Second,
            ReadTimeout:  3 * time.Second,
            WriteTimeout: 3 * time.Second,
            PoolSize:     10,
            MinIdleConns: 5,
        })
    }

    if _, err := Client.Ping(ctx).Result(); err != nil {
        log.Fatalf("Failed to connect to Redis: %v", err)
    }
    
    log.Println("Redis connected successfully")
}

func Set(key string, value interface{}, exp time.Duration) error {
    return Client.Set(ctx, key, value, exp).Err()
}

func Get(key string) (string, error) {
    return Client.Get(ctx, key).Result()
}

func Del(keys ...string) error {
    return Client.Del(ctx, keys...).Err()
}

func Pipeline() redis.Pipeliner {
    return Client.Pipeline()
}
