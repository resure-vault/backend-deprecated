package main

import (
	"log"
	"os"
	"time"

	"secrets-vault-backend/internal/config"
	"secrets-vault-backend/internal/database"
	"secrets-vault-backend/internal/handlers"
	"secrets-vault-backend/internal/middleware"

	"github.com/gin-contrib/cache"
	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	cfg := config.Load()

	db, err := database.Initialize(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	database.InitializeRedis(cfg)

	redisStore := persistence.NewRedisCacheWithURL(cfg.Redis.URL, time.Hour)

	gin.SetMode(gin.ReleaseMode)
	if os.Getenv("GIN_MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()

	router.Use(middleware.Logger())
	router.Use(middleware.CORS())
	router.Use(gin.Recovery())

	router.GET("/health", cache.CachePage(redisStore, 30*time.Second, func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	}))

	api := router.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/signup", handlers.Signup(db))
			auth.POST("/login", handlers.Login(db))
			// allow clients to validate a token or API key and get basic user info
			auth.GET("/me", handlers.Me(db))
		}

		protected := api.Group("/")
		protected.Use(middleware.AuthRequired(db))
		{
			protected.POST("/secrets", handlers.CreateSecret(db))
			protected.PUT("/secrets/:id", handlers.UpdateSecret(db))
			protected.DELETE("/secrets/:id", handlers.DeleteSecret(db))

			protected.GET("/apikeys", handlers.GetAPIKeys(db))
			protected.POST("/apikeys", handlers.CreateAPIKey(db))
			protected.DELETE("/apikeys/:id", handlers.DeleteAPIKey(db))
		}

		apiProtected := api.Group("/")
		apiProtected.Use(handlers.ValidateAPIKey(db))
		{
			apiProtected.GET("/secrets", handlers.GetSecrets(db))
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
