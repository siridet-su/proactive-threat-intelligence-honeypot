package main

import (
	"testing"
	"time"
)

func TestDeferRecordForQuota(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 34, 56, 0, time.UTC)
	record, deferred := deferRecordForQuota(enrichmentRecord{QueriedAt: now}, &quotaExhaustedError{
		provider: "abuseipdb", window: "minute", retryAfter: 4 * time.Second,
	})
	if !deferred || record.Status != "deferred" {
		t.Fatalf("expected deferred record, got %#v", record)
	}
	if record.Summary["reason"] != "quota_exhausted" || record.ExpiresAt != now.Add(4*time.Second) {
		t.Fatalf("unexpected deferred record: %#v", record)
	}
}

func TestQuotaWindowBoundaries(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 34, 56, 0, time.UTC)
	if got := untilNextMinute(now); got != 4*time.Second {
		t.Fatalf("minute retry = %s, want 4s", got)
	}
	if got := untilNextUTCDay(now); got != 11*time.Hour+25*time.Minute+4*time.Second {
		t.Fatalf("day retry = %s", got)
	}
}
