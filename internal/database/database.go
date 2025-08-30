package database

import (
	"fmt"
	"log"
	"os"

	"secrets-vault-backend/internal/config"
	"secrets-vault-backend/internal/models"
	"secrets-vault-backend/internal/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Initialize(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	schema := cfg.Database.Schema
	if schema == "" {
		schema = "public"
	}

	if err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		return nil, fmt.Errorf("failed to create schema '%s': %w", schema, err)
	}

	if err := db.Exec(fmt.Sprintf("SET search_path TO %s", schema)).Error; err != nil {
		return nil, fmt.Errorf("failed to set search_path to '%s': %w", schema, err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := db.Exec("UPDATE users SET name = 'Unknown User' WHERE name IS NULL OR name = ''").Error; err != nil {
		log.Printf("Warning: Failed to update existing user names: %v", err)
	}

	if err := db.Exec("ALTER TABLE users ALTER COLUMN name SET NOT NULL").Error; err != nil {
		log.Printf("Warning: Failed to set name column to NOT NULL: %v", err)
	}

	log.Println("Database connection established successfully")
	return db, nil
}

func runMigrations(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&models.User{},
		&models.Secret{},
		&models.APIKey{},
	); err != nil {
		return err
	}

	// Attempt to migrate any existing plaintext API keys (starting with svp_) to HMAC-hashed values.
	if err := migrateAPIKeysToHashed(db); err != nil {
		return fmt.Errorf("failed to migrate api keys: %w", err)
	}

	return nil
}

// migrateAPIKeysToHashed finds API keys that look like raw tokens (prefix svp_) and replaces them
// with an HMAC-SHA256 (base64) using the HMAC_PEPPER environment variable. The HMAC pepper must
// be provided via the deployment environment and kept secret (never fuck this up)

func migrateAPIKeysToHashed(db *gorm.DB) error {
	hmacPepper := os.Getenv("HMAC_PEPPER")
	if hmacPepper == "" {
		log.Println("HMAC_PEPPER not set; skipping API key hashing migration")
		return nil
	}

	var keys []models.APIKey
	if err := db.Where("key LIKE ?", "svp_%").Find(&keys).Error; err != nil {
		return err
	}

	if len(keys) == 0 {
		log.Println("No plaintext API keys found; skipping migration")
		return nil
	}

	tx := db.Begin()
	migrated := 0
	for _, k := range keys {
		hashed, err := utils.HashAPIKey(k.Key, hmacPepper)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Model(&models.APIKey{}).Where("id = ?", k.ID).Update("key", hashed).Error; err != nil {
			tx.Rollback()
			return err
		}
		migrated++
	}

	if err := tx.Commit().Error; err != nil {
		return err
	}

	log.Printf("Migrated %d API keys to HMAC-hashed values", migrated)
	return nil
}
