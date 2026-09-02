package main

import (
	"strings"
	"testing"
)

func TestValidateJob(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	if err := validateJob(threatIntelJob{
		JobID: "vt", SourceEventID: "event-1", Provider: "virustotal",
		ObservableType: "sha256", Observable: validHash, SchemaVersion: "v1",
	}); err != nil {
		t.Fatalf("valid VirusTotal job rejected: %v", err)
	}
	if err := validateJob(threatIntelJob{
		JobID: "abuse", SourceEventID: "event-1", Provider: "abuseipdb",
		ObservableType: "ip", Observable: "8.8.8.8", SchemaVersion: "v1",
	}); err != nil {
		t.Fatalf("valid AbuseIPDB job rejected: %v", err)
	}
}

func TestValidateJobRejectsUnsafeObservable(t *testing.T) {
	job := threatIntelJob{
		JobID: "private", SourceEventID: "event-1", Provider: "abuseipdb",
		ObservableType: "ip", Observable: "10.0.0.2", SchemaVersion: "v1",
	}
	if err := validateJob(job); err == nil {
		t.Fatal("private IP was accepted")
	}

	job = threatIntelJob{
		JobID: "bad-hash", SourceEventID: "event-1", Provider: "virustotal",
		ObservableType: "sha256", Observable: strings.Repeat("z", 64), SchemaVersion: "v1",
	}
	if err := validateJob(job); err == nil {
		t.Fatal("non-hex SHA-256 was accepted")
	}
}
