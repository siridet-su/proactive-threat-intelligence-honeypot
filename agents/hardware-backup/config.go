package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	defaultMongoDatabase      = "honeypot_db"
	defaultCollection         = "hardware_metrics_1m"
	defaultBackupRoot         = "/var/lib/honeypot/hardware-backups"
	defaultLookbackDays       = 30
	defaultSafetyDays         = 2
	defaultControlPollSeconds = 15
)

type Config struct {
	Mode          string
	MongoURI      string
	MongoDatabase string
	Collection    string
	Targets       []BackupTarget

	B2Bucket             string
	LegacyManifestBucket string
	B2Endpoint           string
	B2KeyID              string
	B2ApplicationKey     string
	BackupRoot           string
	LookbackDays         int
	SafetyDays           int
	ControlPollSeconds   int
	Force                bool
	AllowSensitive       bool
}

func loadConfig() (Config, error) {
	legacyCollection := getenv("BACKUP_COLLECTION", defaultCollection)
	targets, targetErr := configuredBackupTargets(os.Getenv("BACKUP_TARGETS"), legacyCollection)
	if targetErr != nil {
		return Config{}, targetErr
	}
	lookbackDays, err := optionalInt("BACKUP_LOOKBACK_DAYS", defaultLookbackDays, 1)
	if err != nil {
		return Config{}, err
	}
	safetyDays, err := optionalInt("BACKUP_SAFETY_DAYS", defaultSafetyDays, 0)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Mode:                 getenv("BACKUP_MODE", "scheduled"),
		MongoURI:             strings.TrimSpace(os.Getenv("MONGO_URI")),
		MongoDatabase:        getenv("MONGO_DATABASE", defaultMongoDatabase),
		Collection:           targets[0].ID,
		Targets:              targets,
		B2Bucket:             strings.TrimSpace(os.Getenv("B2_BUCKET")),
		LegacyManifestBucket: strings.TrimSpace(os.Getenv("BACKUP_LEGACY_MANIFEST_BUCKET")),
		B2Endpoint:           strings.TrimSpace(os.Getenv("B2_ENDPOINT")),
		B2KeyID:              strings.TrimSpace(os.Getenv("B2_KEY_ID")),
		B2ApplicationKey:     strings.TrimSpace(os.Getenv("B2_APPLICATION_KEY")),
		BackupRoot:           getenv("BACKUP_ROOT", defaultBackupRoot),
		LookbackDays:         lookbackDays,
		SafetyDays:           safetyDays,
		ControlPollSeconds:   getenvPositiveInt("BACKUP_CONTROL_POLL_SECONDS", defaultControlPollSeconds),
		Force:                strings.EqualFold(strings.TrimSpace(os.Getenv("BACKUP_FORCE")), "true"),
		AllowSensitive:       strings.EqualFold(strings.TrimSpace(os.Getenv("BACKUP_ALLOW_SENSITIVE")), "true"),
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
	if cfg.Mode != "scheduled" && cfg.Mode != "control" {
		return Config{}, fmt.Errorf("BACKUP_MODE must be scheduled or control")
	}
	if cfg.LookbackDays <= cfg.SafetyDays {
		return Config{}, fmt.Errorf("BACKUP_LOOKBACK_DAYS must be greater than BACKUP_SAFETY_DAYS")
	}
	for _, target := range cfg.Targets {
		if target.Sensitive && !cfg.AllowSensitive {
			return Config{}, fmt.Errorf("backup target %q contains sensitive event fields; set BACKUP_ALLOW_SENSITIVE=true only after the private B2 policy is ready", target.ID)
		}
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

func optionalInt(key string, fallback, minimum int) (int, error) {
	raw, set := os.LookupEnv(key)
	if !set {
		return fallback, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < minimum {
		return 0, fmt.Errorf("%s must be an integer >= %d", key, minimum)
	}
	return value, nil
}
