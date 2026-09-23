package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	defaultMongoDatabase = "honeypot_db"
	defaultCollection    = "hardware_metrics_1m"
	defaultBackupRoot    = "/var/lib/honeypot/hardware-backups"
	defaultLookbackDays  = 30
	defaultSafetyDays    = 2
)

type Config struct {
	MongoURI      string
	MongoDatabase string
	Collection    string

	B2Bucket         string
	B2Endpoint       string
	B2KeyID          string
	B2ApplicationKey string
	BackupRoot       string
	LookbackDays     int
	SafetyDays       int
	Force            bool
}

func loadConfig() (Config, error) {
	cfg := Config{
		MongoURI:         strings.TrimSpace(os.Getenv("MONGO_URI")),
		MongoDatabase:    getenv("MONGO_DATABASE", defaultMongoDatabase),
		Collection:       getenv("BACKUP_COLLECTION", defaultCollection),
		B2Bucket:         strings.TrimSpace(os.Getenv("B2_BUCKET")),
		B2Endpoint:       strings.TrimSpace(os.Getenv("B2_ENDPOINT")),
		B2KeyID:          strings.TrimSpace(os.Getenv("B2_KEY_ID")),
		B2ApplicationKey: strings.TrimSpace(os.Getenv("B2_APPLICATION_KEY")),
		BackupRoot:       getenv("BACKUP_ROOT", defaultBackupRoot),
		LookbackDays:     getenvPositiveInt("BACKUP_LOOKBACK_DAYS", defaultLookbackDays),
		SafetyDays:       getenvNonNegativeInt("BACKUP_SAFETY_DAYS", defaultSafetyDays),
		Force:            strings.EqualFold(strings.TrimSpace(os.Getenv("BACKUP_FORCE")), "true"),
	}

	for name, value := range map[string]string{
		"MONGO_URI":          cfg.MongoURI,
		"B2_BUCKET":          cfg.B2Bucket,
		"B2_KEY_ID":          cfg.B2KeyID,
		"B2_APPLICATION_KEY": cfg.B2ApplicationKey,
	} {
		if value == "" {
			return Config{}, fmt.Errorf("%s is required", name)
		}
	}
	if cfg.LookbackDays < cfg.SafetyDays+1 {
		return Config{}, fmt.Errorf("BACKUP_LOOKBACK_DAYS must be greater than BACKUP_SAFETY_DAYS")
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvPositiveInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func getenvNonNegativeInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}
