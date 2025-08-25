package middleware

import (
    "net/http"
    "strings"
    "log"

    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
    "secrets-vault-backend/internal/models"
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
        var keyRecord models.APIKey
        err := db.Where("key = ? AND is_active = ?", apiKey, true).First(&keyRecord).Error
        // err := db.Where("key = ? AND active = ?", apiKey, true).First(&keyRecord).Error
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
