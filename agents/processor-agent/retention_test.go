package main

import (
	"testing"
	"time"
)

func TestSetEventExpiryUsesObservedTimestamp(t *testing.T) {
	observedAt := time.Date(2026, 8, 26, 8, 0, 0, 0, time.FixedZone("ICT", 7*60*60))
	event := map[string]any{"timestamp": observedAt}

	setEventExpiry(event, 30*24*time.Hour)

	expiresAt, ok := event["expires_at"].(time.Time)
	if !ok {
		t.Fatal("expires_at was not written as time.Time")
	}
	want := observedAt.UTC().Add(30 * 24 * time.Hour)
	if !expiresAt.Equal(want) {
		t.Fatalf("expires_at = %s, want %s", expiresAt, want)
	}
}

func TestSetHardwareMetricExpiryUsesSampleTimestamp(t *testing.T) {
	observedAt := time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC)
	metric := map[string]interface{}{}

	setHardwareMetricExpiry(metric, observedAt, 48*time.Hour)

	if got := metric["timestamp"]; got != observedAt {
		t.Fatalf("timestamp = %#v, want %#v", got, observedAt)
	}
	if got := metric["expires_at"]; got != observedAt.Add(48*time.Hour) {
		t.Fatalf("expires_at = %#v, want %#v", got, observedAt.Add(48*time.Hour))
	}
}

func TestGetenvPositiveDurationRejectsInvalidAndZeroValues(t *testing.T) {
	t.Setenv("RETENTION_TEST_DURATION", "invalid")
	if got := getenvPositiveDuration("RETENTION_TEST_DURATION", time.Hour); got != time.Hour {
		t.Fatalf("invalid duration = %s, want fallback", got)
	}
	t.Setenv("RETENTION_TEST_DURATION", "0s")
	if got := getenvPositiveDuration("RETENTION_TEST_DURATION", time.Hour); got != time.Hour {
		t.Fatalf("zero duration = %s, want fallback", got)
	}
}
