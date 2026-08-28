package main

import (
	"strings"
	"testing"
)

func TestBuildThreatIntelJobsUsesOnlySafeObservables(t *testing.T) {
	hash := strings.Repeat("A", 64)
	jobs := buildThreatIntelJobs("cowrie", "event-1", "cowrie.session.file_download", "8.8.8.8", map[string]any{
		"session": "session-1",
		"shasum":  hash,
	})
	if len(jobs) != 2 {
		t.Fatalf("expected IP and hash jobs, got %#v", jobs)
	}

	if jobs[0].Provider != "abuseipdb" || jobs[0].Observable != "8.8.8.8" {
		t.Fatalf("unexpected IP job: %#v", jobs[0])
	}
	if jobs[1].Provider != "virustotal" || jobs[1].Observable != strings.ToLower(hash) {
		t.Fatalf("unexpected hash job: %#v", jobs[1])
	}
	if jobs[1].SessionID != "session-1" || jobs[1].Priority != "high" {
		t.Fatalf("missing job context: %#v", jobs[1])
	}
}

func TestBuildThreatIntelJobsRejectsPrivateAndInvalidValues(t *testing.T) {
	jobs := buildThreatIntelJobs("cowrie", "event-2", "cowrie.session.connect", "192.168.1.5", map[string]any{
		"shasum": "not-a-sha256",
	})
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs for private IP and invalid hash, got %#v", jobs)
	}
}

func TestIsQueryablePublicIP(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if !isQueryablePublicIP(value) {
			t.Fatalf("expected %s to be queryable", value)
		}
	}
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.1.1", "invalid"} {
		if isQueryablePublicIP(value) {
			t.Fatalf("expected %s not to be queryable", value)
		}
	}
}
