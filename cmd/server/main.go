package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"secrets-vault-backend/internal/config"
	"secrets-vault-backend/internal/database"
	"secrets-vault-backend/internal/handlers"
	"secrets-vault-backend/internal/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	cfg := config.Load()

	// Initialize database
	db, err := database.Initialize(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	if os.Getenv("GIN_MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()

	// middleware
	router.Use(middleware.Logger())
	router.Use(middleware.CORS())
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := router.Group("/api/v1")
	{
		// Authentication routes
		auth := api.Group("/auth")
		{
			auth.POST("/signup", handlers.Signup(db))
			auth.POST("/login", handlers.Login(db))
		}

		// Protected routes
		protected := api.Group("/")
		protected.Use(middleware.AuthRequired(db))
		{
			// Secrets management
			protected.GET("/secrets", handlers.GetSecrets(db))
			protected.POST("/secrets", handlers.CreateSecret(db))
			protected.PUT("/secrets/:id", handlers.UpdateSecret(db))
			protected.DELETE("/secrets/:id", handlers.DeleteSecret(db))

			// API key management
			protected.GET("/apikeys", handlers.GetAPIKeys(db))
			protected.POST("/apikeys", handlers.CreateAPIKey(db))
			protected.DELETE("/apikeys/:id", handlers.DeleteAPIKey(db))
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
