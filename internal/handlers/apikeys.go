package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"secrets-vault-backend/internal/models"
)

func GetAPIKeys(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		var apiKeys []models.APIKey

		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		offset := (page - 1) * limit

		query := db.Where("user_id = ?", u.ID).
			Order("created_at DESC").
			Limit(limit).
			Offset(offset)

		if status := c.Query("status"); status == "active" {
			query = query.Where("is_active = ?", true)
		} else if status == "inactive" {
			query = query.Where("is_active = ?", false)
		}

		if err := query.Find(&apiKeys).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve API keys"})
			return
		}
		for i := range apiKeys {
			if len(apiKeys[i].Key) > 8 {
				apiKeys[i].Key = apiKeys[i].Key[:8] + "..."
			}
		}

		var total int64
		countQuery := db.Model(&models.APIKey{}).Where("user_id = ?", u.ID)
		if status := c.Query("status"); status == "active" {
			countQuery = countQuery.Where("is_active = ?", true)
		} else if status == "inactive" {
			countQuery = countQuery.Where("is_active = ?", false)
		}
		countQuery.Count(&total)

		c.JSON(http.StatusOK, gin.H{
			"api_keys": apiKeys,
			"pagination": gin.H{
				"page":  page,
				"limit": limit,
				"total": total,
			},
		})
	}
}

func CreateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		var req models.CreateAPIKeyRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
			return
		}

		if strings.TrimSpace(req.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "API key name is required"})
			return
		}

		var existingKey models.APIKey
		if err := db.Where("user_id = ? AND name = ?", u.ID, req.Name).First(&existingKey).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "API key with this name already exists"})
			return
		}

		var keyCount int64
		db.Model(&models.APIKey{}).Where("user_id = ? AND is_active = ?", u.ID, true).Count(&keyCount)
		if keyCount >= 10 { // Limit to 10 active keys per user
			c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum number of API keys reached (10)"})
			return
		}

		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate secure API key"})
			return
		}

		apiKeyString := "sm_" + hex.EncodeToString(keyBytes)

		var existingKeyCheck models.APIKey
		for {
			if err := db.Where("key = ?", apiKeyString).First(&existingKeyCheck).Error; err != nil {
				break
			}
			rand.Read(keyBytes)
			apiKeyString = "svp_" + hex.EncodeToString(keyBytes)
		}

		apiKey := models.APIKey{
			UserID:    u.ID,
			Name:      strings.TrimSpace(req.Name),
			Key:       apiKeyString,
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := db.Create(&apiKey).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save API key"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "API key created successfully",
			"api_key": gin.H{
				"id":         apiKey.ID,
				"name":       apiKey.Name,
				"key":        apiKey.Key,
				"is_active":  apiKey.IsActive,
				"created_at": apiKey.CreatedAt,
			},
			"warning": "This is the only time the full API key will be displayed. Store it securely.",
		})
	}
}

func UpdateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		keyID := c.Param("id")

		var apiKey models.APIKey
		if err := db.Where("id = ? AND user_id = ?", keyID, u.ID).First(&apiKey).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		var req struct {
			Name     string `json:"name"`
			IsActive *bool  `json:"is_active"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		if req.Name != "" {
			var existingKey models.APIKey
			if err := db.Where("user_id = ? AND name = ? AND id != ?", u.ID, req.Name, keyID).First(&existingKey).Error; err == nil {
				c.JSON(http.StatusConflict, gin.H{"error": "API key with this name already exists"})
				return
			}
			apiKey.Name = strings.TrimSpace(req.Name)
		}

		if req.IsActive != nil {
			apiKey.IsActive = *req.IsActive
			
			if *req.IsActive {
				now := time.Now()
				apiKey.LastUsed = &now
			}
		}

		apiKey.UpdatedAt = time.Now()

		if err := db.Save(&apiKey).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update API key"})
			return
		}

		apiKey.Key = "Hidden for security"
		c.JSON(http.StatusOK, gin.H{
			"message": "API key updated successfully",
			"api_key": apiKey,
		})
	}
}

func DeleteAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		keyID := c.Param("id")

		var apiKey models.APIKey
		if err := db.Where("id = ? AND user_id = ?", keyID, u.ID).First(&apiKey).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		if err := db.Delete(&apiKey).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "API key deleted successfully",
			"id":      keyID,
			"name":    apiKey.Name,
		})
	}
}

func ValidateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				apiKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		if !strings.HasPrefix(apiKey, "svp_") || len(apiKey) != 68 { // svp_ + 64 hex chars
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key format"})
			c.Abort()
			return
		}

		var keyRecord models.APIKey
		if err := db.Where("key = ? AND is_active = ?", apiKey, true).First(&keyRecord).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive API key"})
			c.Abort()
			return
		}

		now := time.Now()
		keyRecord.LastUsed = &now
		db.Save(&keyRecord)

		var user models.User
		if err := db.First(&user, keyRecord.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("api_key", keyRecord)
		c.Next()
	}
}

func RevokeAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		keyID := c.Param("id")

		var apiKey models.APIKey
		if err := db.Where("id = ? AND user_id = ?", keyID, u.ID).First(&apiKey).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		apiKey.IsActive = false
		apiKey.UpdatedAt = time.Now()

		if err := db.Save(&apiKey).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "API key revoked successfully",
			"id":      keyID,
			"name":    apiKey.Name,
		})
	}
}
