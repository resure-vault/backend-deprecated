package handlers

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"secrets-vault-backend/internal/models"
	"secrets-vault-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgconn"
	"gorm.io/gorm"
)

func Signup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.SignupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// hash passwords before creating the user
		hashedPassword, err := utils.HashPassword(req.Password)
		if err != nil {
			log.Printf("error hashing password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}

		hashedMasterPassword, err := utils.HashPassword(req.MasterPassword)
		if err != nil {
			log.Printf("error hashing master password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}

		user := models.User{
			Email:              req.Email,
			Password:           hashedPassword,
			MasterPasswordHash: hashedMasterPassword,
		}

		tx := db.Begin()
		if tx.Error != nil {
			log.Printf("failed to begin transaction: %v", tx.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}

		if err := tx.Create(&user).Error; err != nil {
			tx.Rollback()
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				if pgErr.Code == "23505" {
					c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
					return
				}
			}

			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") {
				c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
				return
			}

			log.Printf("failed to create user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		if err := tx.Commit().Error; err != nil {
			log.Printf("failed to commit transaction: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		// issue jwt token
		token, err := utils.GenerateJWT(user.ID)
		if err != nil {
			log.Printf("failed to generate token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusCreated, models.LoginResponse{
			User:  user,
			Token: token,
		})
	}
}

func Login(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user models.User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
				return
			}
			// other db error
			log.Printf("db error during login lookup: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}

		if !utils.CheckPasswordHash(req.Password, user.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		if !utils.CheckPasswordHash(req.MasterPassword, user.MasterPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid master password"})
			return
		}

		token, err := utils.GenerateJWT(user.ID)
		if err != nil {
			log.Printf("failed to generate token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, models.LoginResponse{
			User:  user,
			Token: token,
		})
	}
}
