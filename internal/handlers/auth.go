package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"secrets-vault-backend/internal/database"
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

		// trim inputs to avoid accidental whitespace mismatches
		req.Email = strings.TrimSpace(req.Email)
		req.Password = strings.TrimSpace(req.Password)
		req.MasterPassword = strings.TrimSpace(req.MasterPassword)

		if req.Email == "" || req.Password == "" || req.MasterPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email, password and master_password are required"})
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

		// sanity check the generated hashes by verifying they match the original plaintexts
		// this should always succeed; if it doesn't, it's an internal error worth failing fast on :c
		if !utils.CheckPasswordHash(req.Password, hashedPassword) {
			log.Printf("signup: hashed password verification failed (email=%s)", req.Email)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}
		if !utils.CheckPasswordHash(req.MasterPassword, hashedMasterPassword) {
			log.Printf("signup: hashed master password verification failed (email=%s)", req.Email)
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

		// trim inputs
		req.Email = strings.TrimSpace(req.Email)
		req.Password = strings.TrimSpace(req.Password)
		req.MasterPassword = strings.TrimSpace(req.MasterPassword)

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

// /me returns current authenticated user's basic information (id and email).
// this handler will accept either a Bearer JWT or an API key provided via X-API-Key or Authorization header.
// todo: accept api keys only from cli

func Me(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// if middleware already set the user, return it
		if u, ok := c.Get("user"); ok {
			user := u.(models.User)
			c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
			return
		}

		//  try JWT from Authorization: Bearer <token>
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tokenString := strings.TrimPrefix(auth, "Bearer ")
			if claims, err := utils.ValidateJWT(tokenString); err == nil {
				var user models.User
				if db.First(&user, claims.UserID).Error == nil {
					c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
					return
				}
			}
		}

		// try API key from X-API-Key or Authorization header (Bearer <key> where key starts with svp_)
		key := c.GetHeader("X-API-Key")
		if key == "" {
			// maybe provided as Bearer header (client might send svp_ token as bearer)
			auth = c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				maybe := strings.TrimPrefix(auth, "Bearer ")
				if strings.HasPrefix(maybe, "svp_") {
					key = maybe
				}
			}
		}

		if key != "" {
			if !strings.HasPrefix(key, "svp_") || len(key) != 68 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
				return
			}

			// check cache first
			if userIDStr, err := database.Get(fmt.Sprintf(keyValidPrefix, key)); err == nil {
				if uid, err := strconv.Atoi(userIDStr); err == nil {
					var user models.User
					if db.First(&user, uid).Error == nil {
						c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
						return
					}
				}
			}

			// fallback db lookup
			var keyRecord models.APIKey
			if db.Where("key = ? AND is_active = ?", key, true).First(&keyRecord).Error != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
				return
			}

			var user models.User
			if db.First(&user, keyRecord.UserID).Error != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
				return
			}

			// cache valid key
			database.Set(fmt.Sprintf(keyValidPrefix, key), user.ID, validTTL)

			c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
	}
}
