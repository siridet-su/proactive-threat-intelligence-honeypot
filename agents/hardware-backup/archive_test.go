package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveObjectNameUsesUTCDate(t *testing.T) {
	day := time.Date(2026, 9, 23, 23, 30, 0, 0, time.FixedZone("UTC+7", 7*60*60))
	got := archiveObjectName(day)
	want := filepath.ToSlash("hardware_metrics_1m/2026/09/23/rollup.jsonl.gz")
	if got != want {
		t.Fatalf("archiveObjectName() = %q, want %q", got, want)
	}
}

func TestHashFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.gz")
	if err := os.WriteFile(path, []byte("hardware backup\n"), 0o600); err != nil {
		t.Fatalf("write test archive: %v", err)
	}

	sha1Hex, sha256Hex, size, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile() error = %v", err)
	}
	if size != int64(len("hardware backup\n")) {
		t.Fatalf("size = %d, want %d", size, len("hardware backup\n"))
	}
	if sha1Hex != "caa6aca5f29c7f363f0594f8ee89b67a1a94969e" {
		t.Fatalf("sha1 = %q", sha1Hex)
	}
	if sha256Hex != "fe7bb7bcdf95d41f2542b2d0710fad29827dac5f3f709f472ab757a6ae3f689e" {
		t.Fatalf("sha256 = %q", sha256Hex)
	}
}
