package database

import (
	"fmt"
	"log"

	"secrets-vault-backend/internal/config"
	"secrets-vault-backend/internal/models"

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

	// check if requested schema exists and set the search_path to the latter before migrations
	schema := cfg.Database.Schema
	if schema == "" {
		schema = "public"
	}

	// create schema if not exists and set search_path
	if err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		return nil, fmt.Errorf("failed to create schema '%s': %w", schema, err)
	}

	if err := db.Exec(fmt.Sprintf("SET search_path TO %s", schema)).Error; err != nil {
		return nil, fmt.Errorf("failed to set search_path to '%s': %w", schema, err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Database connection established successfully")
	return db, nil
}

func runMigrations(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.Secret{},
		&models.APIKey{},
	)
}
