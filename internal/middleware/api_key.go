package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"

	"secrets-vault-backend/internal/models"
	"secrets-vault-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func ValidateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}
		if !strings.HasPrefix(apiKey, "svp_") || len(apiKey) != 68 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key format"})
			c.Abort()
			return
		}

		// HMAC pepper must be provided via environment (kept out of repo)
		hmacPepper := os.Getenv("HMAC_PEPPER")
		if hmacPepper == "" {
			log.Printf("HMAC_PEPPER not set")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
			c.Abort()
			return
		}

		// compute keyed hash of provided token and query by hashed value
		hashed, err := utils.HashAPIKey(apiKey, hmacPepper)
		if err != nil {
			log.Printf("failed to hash api key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		var keyRecord models.APIKey
		err = db.Where("key = ? AND is_active = ?", hashed, true).First(&keyRecord).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				log.Printf("API key not found or inactive: %s", apiKey[:12]+"...")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive API key"})
			} else {
				log.Printf("Database error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			}
			c.Abort()
			return
		}
		var user models.User
		err = db.First(&user, keyRecord.UserID).Error
		if err != nil {
			log.Printf("User not found for API key: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}
		c.Set("user", user)
		c.Set("api_key", keyRecord)
		c.Next()
	}
}
