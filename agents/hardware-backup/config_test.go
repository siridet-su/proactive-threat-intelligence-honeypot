package main

import "testing"

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-hardware-backups")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.MongoDatabase != defaultMongoDatabase {
		t.Fatalf("MongoDatabase = %q, want %q", cfg.MongoDatabase, defaultMongoDatabase)
	}
	if cfg.Collection != defaultCollection {
		t.Fatalf("Collection = %q, want %q", cfg.Collection, defaultCollection)
	}
	if cfg.LookbackDays != defaultLookbackDays {
		t.Fatalf("LookbackDays = %d, want %d", cfg.LookbackDays, defaultLookbackDays)
	}
	if cfg.SafetyDays != defaultSafetyDays {
		t.Fatalf("SafetyDays = %d, want %d", cfg.SafetyDays, defaultSafetyDays)
	}
	if cfg.Mode != "scheduled" {
		t.Fatalf("Mode = %q, want scheduled", cfg.Mode)
	}
	if cfg.ControlPollSeconds != defaultControlPollSeconds {
		t.Fatalf("ControlPollSeconds = %d, want %d", cfg.ControlPollSeconds, defaultControlPollSeconds)
	}
}

func TestLoadConfigRejectsUnsafeRange(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-hardware-backups")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_LOOKBACK_DAYS", "2")
	t.Setenv("BACKUP_SAFETY_DAYS", "2")

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig() error = nil, want unsafe range error")
	}
}

func TestLoadConfigControlMode(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-hardware-backups")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_MODE", "control")
	t.Setenv("BACKUP_CONTROL_POLL_SECONDS", "7")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.Mode != "control" {
		t.Fatalf("Mode = %q, want control", cfg.Mode)
	}
	if cfg.ControlPollSeconds != 7 {
		t.Fatalf("ControlPollSeconds = %d, want 7", cfg.ControlPollSeconds)
	}
}
