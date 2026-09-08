package main

import (
	"testing"
	"time"
)

func cwdEventForTest(eventID string) map[string]any {
	return map[string]any{
		"source":    "cowrie",
		"event_id":  eventID,
		"timestamp": time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		"network":   map[string]any{"src_ip": "198.51.100.7"},
	}
}

func TestCwdObservationFromCommandUsesCowrieCwdBefore(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-command"), map[string]any{
		"eventid": "cowrie.command.input", "session": "session-1", "cwd_before": "/home/operator",
	})
	if !ok {
		t.Fatal("expected authoritative command CWD observation")
	}
	if observation.Path != "/home/operator" || observation.Action != "observed" || observation.Status != "observed" {
		t.Fatalf("unexpected observation: %#v", observation)
	}
}

func TestCwdObservationFromChangeRequiresCanonicalCowriePath(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-change"), map[string]any{
		"eventid": "cowrie.session.cwd", "session": "session-1", "cwd_before": "/home/operator", "cwd": "/var/tmp", "cwd_action": "changed", "cwd_status": "confirmed",
	})
	if !ok || observation.Path != "/var/tmp" || observation.FromPath != "/home/operator" || observation.Status != "confirmed" {
		t.Fatalf("unexpected change observation: %#v ok=%v", observation, ok)
	}

	_, ok = cwdObservationFromEvent(cwdEventForTest("raw-noncanonical"), map[string]any{
		"eventid": "cowrie.session.cwd", "session": "session-1", "cwd_before": "/home/operator", "cwd": "/var/../tmp", "cwd_action": "changed",
	})
	if ok {
		t.Fatal("non-canonical path must be rejected, not rewritten")
	}
}

func TestCwdFailureDoesNotPersistAttackerTargetAsCurrentPath(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-failed"), map[string]any{
		"eventid": "cowrie.session.cwd", "session": "session-1", "cwd_before": "/home/operator", "cwd": "/etc", "cwd_action": "failed_change", "cwd_status": "unknown",
	})
	if !ok {
		t.Fatal("expected failed CWD observation")
	}
	if observation.Path != "/home/operator" || observation.Action != "failed_change" || observation.Status != "observed" {
		t.Fatalf("failed change must retain current observed CWD: %#v", observation)
	}
}
