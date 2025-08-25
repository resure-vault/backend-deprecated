package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"secrets-vault-backend/internal/models"
	"secrets-vault-backend/internal/utils"
)

func GetSecrets(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		var secrets []models.Secret

		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset := (page - 1) * limit

		query := db.Where("user_id = ?", u.ID).
			Order("updated_at DESC").
			Limit(limit).
			Offset(offset)

		if category := c.Query("category"); category != "" && category != "All" {
			query = query.Where("category = ?", category)
		}

		if search := c.Query("search"); search != "" {
			searchTerm := "%" + strings.ToLower(search) + "%"
			query = query.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", searchTerm, searchTerm)
		}

		if err := query.Find(&secrets).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve secrets"})
			return
		}

		var total int64
		countQuery := db.Model(&models.Secret{}).Where("user_id = ?", u.ID)
		if category := c.Query("category"); category != "" && category != "All" {
			countQuery = countQuery.Where("category = ?", category)
		}
		if search := c.Query("search"); search != "" {
			searchTerm := "%" + strings.ToLower(search) + "%"
			countQuery = countQuery.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", searchTerm, searchTerm)
		}
		countQuery.Count(&total)

		c.JSON(http.StatusOK, gin.H{
			"secrets": secrets,
			"pagination": gin.H{
				"page":  page,
				"limit": limit,
				"total": total,
			},
		})
	}
}

func CreateSecret(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		var req models.CreateSecretRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
			return
		}

		if strings.TrimSpace(req.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Secret name is required"})
			return
		}

		if strings.TrimSpace(req.Value) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Secret value is required"})
			return
		}

		var existingSecret models.Secret
		if err := db.Where("user_id = ? AND name = ?", u.ID, req.Name).First(&existingSecret).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Secret with this name already exists"})
			return
		}

		masterPassword := c.GetHeader("X-Master-Password")
		if masterPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Master password required for encryption"})
			return
		}

		if !utils.CheckPasswordHash(masterPassword, u.MasterPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid master password"})
			return
		}

		encryptedValue, err := utils.Encrypt(req.Value, masterPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt secret"})
			return
		}

		category := req.Category
		if category == "" {
			category = "General"
		}

		secret := models.Secret{
			UserID:      u.ID,
			Name:        strings.TrimSpace(req.Name),
			Value:       encryptedValue,
			Category:    category,
			Description: strings.TrimSpace(req.Description),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := db.Create(&secret).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save secret"})
			return
		}

		secret.Value = "[ENCRYPTED]"
		c.JSON(http.StatusCreated, gin.H{
			"message": "Secret created successfully",
			"secret":  secret,
		})
	}
}

func UpdateSecret(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		secretID := c.Param("id")

		var secret models.Secret
		if err := db.Where("id = ? AND user_id = ?", secretID, u.ID).First(&secret).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		var req models.CreateSecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
			return
		}

		if strings.TrimSpace(req.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Secret name is required"})
			return
		}

		var existingSecret models.Secret
		if err := db.Where("user_id = ? AND name = ? AND id != ?", u.ID, req.Name, secretID).First(&existingSecret).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Secret with this name already exists"})
			return
		}

		masterPassword := c.GetHeader("X-Master-Password")
		if masterPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Master password required for encryption"})
			return
		}

		if !utils.CheckPasswordHash(masterPassword, u.MasterPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid master password"})
			return
		}

		if req.Value != "" {
			encryptedValue, err := utils.Encrypt(req.Value, masterPassword)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt secret"})
				return
			}
			secret.Value = encryptedValue
		}

		secret.Name = strings.TrimSpace(req.Name)
		secret.Category = req.Category
		if secret.Category == "" {
			secret.Category = "General"
		}
		secret.Description = strings.TrimSpace(req.Description)
		secret.UpdatedAt = time.Now()

		if err := db.Save(&secret).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update secret"})
			return
		}

		secret.Value = "[ENCRYPTED]"
		c.JSON(http.StatusOK, gin.H{
			"message": "Secret updated successfully",
			"secret":  secret,
		})
	}
}

func DeleteSecret(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		secretID := c.Param("id")

		var secret models.Secret
		if err := db.Where("id = ? AND user_id = ?", secretID, u.ID).First(&secret).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		if err := db.Delete(&secret).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secret"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Secret deleted successfully",
			"id":      secretID,
		})
	}
}

func GetSecret(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		u := user.(models.User)
		secretID := c.Param("id")

		var secret models.Secret
		if err := db.Where("id = ? AND user_id = ?", secretID, u.ID).First(&secret).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		masterPassword := c.GetHeader("X-Master-Password")
		if masterPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Master password required for decryption"})
			return
		}

		if !utils.CheckPasswordHash(masterPassword, u.MasterPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid master password"})
			return
		}

		decryptedValue, err := utils.Decrypt(secret.Value, masterPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt secret"})
			return
		}

		secret.Value = decryptedValue
		c.JSON(http.StatusOK, secret)
	}
}
