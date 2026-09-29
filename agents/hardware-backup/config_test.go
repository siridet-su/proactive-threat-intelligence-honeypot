package main

import (
	"strconv"
	"strings"
	"testing"
)

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

func TestLoadConfigRejectsSafetyDaysAtMaxInt(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-hardware-backups")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_LOOKBACK_DAYS", "30")
	t.Setenv("BACKUP_SAFETY_DAYS", strconv.Itoa(int(^uint(0)>>1)))

	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "BACKUP_LOOKBACK_DAYS") {
		t.Fatalf("loadConfig() error = %v, want unsafe range error", err)
	}
}

func TestLoadConfigRejectsExplicitInvalidBackupWindow(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"empty lookback", "BACKUP_LOOKBACK_DAYS", ""},
		{"non-numeric lookback", "BACKUP_LOOKBACK_DAYS", "abc"},
		{"zero lookback", "BACKUP_LOOKBACK_DAYS", "0"},
		{"overflowed lookback", "BACKUP_LOOKBACK_DAYS", "999999999999999999999999"},
		{"empty safety", "BACKUP_SAFETY_DAYS", ""},
		{"non-numeric safety", "BACKUP_SAFETY_DAYS", "abc"},
		{"negative safety", "BACKUP_SAFETY_DAYS", "-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MONGO_URI", "mongodb://localhost:27017")
			t.Setenv("B2_BUCKET", "pti-hardware-backups")
			t.Setenv("B2_KEY_ID", "key-id")
			t.Setenv("B2_APPLICATION_KEY", "application-key")
			t.Setenv(tt.key, tt.value)
			if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("loadConfig() error = %v, want error naming %s", err, tt.key)
			}
		})
	}
}

func TestLoadConfigAcceptsExplicitBackupWindow(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-hardware-backups")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_LOOKBACK_DAYS", "7")
	t.Setenv("BACKUP_SAFETY_DAYS", "0")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.LookbackDays != 7 || cfg.SafetyDays != 0 {
		t.Fatalf("backup window = %d/%d, want 7/0", cfg.LookbackDays, cfg.SafetyDays)
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

func TestLoadConfigRejectsSensitiveTargetWithoutExplicitOptIn(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-honeypot-archives")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_TARGETS", "hardware_metrics_1m,threat_events")

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig() error = nil, want sensitive-target opt-in error")
	}
}

func TestLoadConfigAcceptsAllTargetsWhenSensitiveOptedIn(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("B2_BUCKET", "pti-honeypot-archives")
	t.Setenv("B2_KEY_ID", "key-id")
	t.Setenv("B2_APPLICATION_KEY", "application-key")
	t.Setenv("BACKUP_TARGETS", "hardware_metrics_1m,threat_events,filesystem_audit")
	t.Setenv("BACKUP_ALLOW_SENSITIVE", "true")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if len(cfg.Targets) != 3 {
		t.Fatalf("Targets = %d, want 3", len(cfg.Targets))
	}
	if !cfg.Targets[1].Sensitive {
		t.Fatal("threat_events target is not marked sensitive")
	}
}
