package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"secrets-vault-backend/internal/database"
	"secrets-vault-backend/internal/models"
	"secrets-vault-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	userKeysPrefix = "uk:%d:%d:%d:%s"
	keyValidPrefix = "kv:%s"
	keyCountPrefix = "kc:%d"
	cacheTTL       = 10 * time.Minute
	validTTL       = time.Hour
	shortTTL       = 5 * time.Minute
)

func GetAPIKeys(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet("user").(models.User)
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		status := c.Query("status")

		cacheKey := fmt.Sprintf(userKeysPrefix, user.ID, page, limit, status)

		if cached, err := database.Get(cacheKey); err == nil {
			var resp gin.H
			json.Unmarshal([]byte(cached), &resp)
			resp["cached"] = true
			c.JSON(http.StatusOK, resp)
			return
		}

		offset := (page - 1) * limit
		query := db.Where("user_id = ?", user.ID).Order("created_at DESC").Limit(limit).Offset(offset)

		switch status {
		case "active":
			query = query.Where("is_active = ?", true)
		case "inactive":
			query = query.Where("is_active = ?", false)
		}

		var keys []models.APIKey
		query.Find(&keys)

		for i := range keys {
			// stored keys are hashed; don't leak hash - show placeholder
			keys[i].Key = "Hidden"
		}

		var total int64
		countQuery := db.Model(&models.APIKey{}).Where("user_id = ?", user.ID)
		switch status {
		case "active":
			countQuery = countQuery.Where("is_active = ?", true)
		case "inactive":
			countQuery = countQuery.Where("is_active = ?", false)
		}
		countQuery.Count(&total)

		resp := gin.H{
			"api_keys":   keys,
			"pagination": gin.H{"page": page, "limit": limit, "total": total},
			"cached":     false,
		}

		if data, _ := json.Marshal(resp); data != nil {
			database.Set(cacheKey, data, cacheTTL)
		}

		c.JSON(http.StatusOK, resp)
	}
}

func CreateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet("user").(models.User)
		var req models.CreateAPIKeyRequest

		if c.ShouldBindJSON(&req) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Name required"})
			return
		}

		var exists models.APIKey
		if db.Where("user_id = ? AND name = ?", user.ID, req.Name).First(&exists).Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Name exists"})
			return
		}

		countKey := fmt.Sprintf(keyCountPrefix, user.ID)
		var count int64

		if cached, err := database.Get(countKey); err == nil {
			count, _ = strconv.ParseInt(cached, 10, 64)
		} else {
			db.Model(&models.APIKey{}).Where("user_id = ? AND is_active = ?", user.ID, true).Count(&count)
			database.Set(countKey, count, shortTTL)
		}

		if count >= 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Limit reached"})
			return
		}

		// generate raw token to show user once
		keyBytes := make([]byte, 32)
		rand.Read(keyBytes)
		rawToken := "svp_" + hex.EncodeToString(keyBytes)

		// HMAC pepper must be provided via environment (kept out of repo)
		hmacPepper := os.Getenv("HMAC_PEPPER")
		if hmacPepper == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
			return
		}

		hashedKey, err := utils.HashAPIKey(rawToken, hmacPepper)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create key"})
			return
		}

		key := models.APIKey{
			UserID:    user.ID,
			Name:      req.Name,
			Key:       hashedKey,
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if db.Create(&key).Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Creation failed"})
			return
		}

		pipe := database.Pipeline()
		pipe.Del(c, fmt.Sprintf("uk:%d:*", user.ID))
		pipe.Set(c, countKey, count+1, shortTTL)
		pipe.Set(c, fmt.Sprintf(keyValidPrefix, hashedKey), user.ID, validTTL)
		pipe.Exec(c)

		c.JSON(http.StatusCreated, gin.H{
			"api_key": gin.H{
				"id":   key.ID,
				"name": key.Name,
				// show raw token once
				"key":        rawToken,
				"is_active":  true,
				"created_at": key.CreatedAt,
			},
			"warning": "Store securely - shown only once",
		})
	}
}

func UpdateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet("user").(models.User)
		keyID := c.Param("id")

		var key models.APIKey
		if db.Where("id = ? AND user_id = ?", keyID, user.ID).First(&key).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}

		wasActive := key.IsActive
		var req struct {
			Name     string `json:"name"`
			IsActive *bool  `json:"is_active"`
		}

		if c.ShouldBindJSON(&req) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format"})
			return
		}

		if req.Name != "" {
			req.Name = strings.TrimSpace(req.Name)
			var exists models.APIKey
			if db.Where("user_id = ? AND name = ? AND id != ?", user.ID, req.Name, keyID).First(&exists).Error == nil {
				c.JSON(http.StatusConflict, gin.H{"error": "Name exists"})
				return
			}
			key.Name = req.Name
		}

		if req.IsActive != nil {
			key.IsActive = *req.IsActive
			if *req.IsActive {
				now := time.Now()
				key.LastUsed = &now
			}
		}

		key.UpdatedAt = time.Now()
		db.Save(&key)

		pipe := database.Pipeline()
		pipe.Del(c, fmt.Sprintf("uk:%d:*", user.ID))

		if wasActive && req.IsActive != nil && !*req.IsActive {
			pipe.Del(c, fmt.Sprintf(keyValidPrefix, key.Key))
			pipe.Del(c, fmt.Sprintf(keyCountPrefix, user.ID))
		} else if !wasActive && req.IsActive != nil && *req.IsActive {
			pipe.Set(c, fmt.Sprintf(keyValidPrefix, key.Key), user.ID, validTTL)
		}
		pipe.Exec(c)

		key.Key = "Hidden"
		c.JSON(http.StatusOK, gin.H{"api_key": key})
	}
}

func DeleteAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet("user").(models.User)
		keyID := c.Param("id")

		var key models.APIKey
		if db.Where("id = ? AND user_id = ?", keyID, user.ID).First(&key).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}

		originalKey := key.Key
		db.Delete(&key)

		database.Del(
			fmt.Sprintf("uk:%d:*", user.ID),
			fmt.Sprintf(keyValidPrefix, originalKey),
			fmt.Sprintf(keyCountPrefix, user.ID),
		)

		c.JSON(http.StatusOK, gin.H{"id": keyID, "name": key.Name})
	}
}

func ValidateAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if key == "" || !strings.HasPrefix(key, "svp_") || len(key) != 68 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
			c.Abort()
			return
		}

		// try cache by hashed key
		hmacPepper := os.Getenv("HMAC_PEPPER")
		if hmacPepper == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
			c.Abort()
			return
		}
		hashed, err := utils.HashAPIKey(key, hmacPepper)
		if err == nil {
			validKey := fmt.Sprintf(keyValidPrefix, hashed)
			if userIDStr, err := database.Get(validKey); err == nil {
				if userID, err := strconv.Atoi(userIDStr); err == nil {
					var user models.User
					if db.First(&user, userID).Error == nil {
						c.Set("user", user)
						c.Next()
						return
					}
				}
			}
		}

		var keyRecord models.APIKey
		if db.Where("key = ? AND is_active = ?", hashed, true).First(&keyRecord).Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
			c.Abort()
			return
		}

		now := time.Now()
		keyRecord.LastUsed = &now
		go db.Save(&keyRecord)

		var user models.User
		if db.First(&user, keyRecord.UserID).Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		database.Set(fmt.Sprintf(keyValidPrefix, keyRecord.Key), user.ID, validTTL)

		c.Set("user", user)
		c.Set("api_key", keyRecord)
		c.Next()
	}
}

func RevokeAPIKey(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet("user").(models.User)
		keyID := c.Param("id")

		var key models.APIKey
		if db.Where("id = ? AND user_id = ?", keyID, user.ID).First(&key).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}

		originalKey := key.Key
		key.IsActive = false
		key.UpdatedAt = time.Now()
		db.Save(&key)

		database.Del(
			fmt.Sprintf("uk:%d:*", user.ID),
			fmt.Sprintf(keyValidPrefix, originalKey),
			fmt.Sprintf(keyCountPrefix, user.ID),
		)

		c.JSON(http.StatusOK, gin.H{"id": keyID, "name": key.Name})
	}
}
