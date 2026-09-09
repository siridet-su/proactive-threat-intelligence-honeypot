package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
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

func TestCwdObservationFromCommandUsesAuthoritativeCowrieCwd(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-command-direct"), map[string]any{
		"eventid": "cowrie.command.input", "session": "session-1",
		"cwd": "/home/operator", "cwd_status": "confirmed",
	})
	if !ok {
		t.Fatal("expected authoritative direct Cowrie CWD")
	}
	if observation.Path != "/home/operator" || observation.Status != "confirmed" {
		t.Fatalf("unexpected direct observation: %#v", observation)
	}
}

func TestCwdObservationAcceptsTimestampSerializedByEnrichment(t *testing.T) {
	// enrichEvent starts by JSON-deep-copying normalized events, so timestamp is
	// an RFC3339 string by the time processMessage records the CWD projection.
	event := deepCopy(cwdEventForTest("raw-command-serialized"))
	observation, ok := cwdObservationFromEvent(event, map[string]any{
		"eventid": "cowrie.command.input", "session": "session-1",
		"cwd": "/home/operator", "cwd_status": "confirmed",
	})
	if !ok {
		t.Fatal("expected CWD observation after timestamp JSON serialization")
	}
	if observation.At.Format(time.RFC3339Nano) != "2026-09-08T12:00:00Z" {
		t.Fatalf("unexpected parsed timestamp: %s", observation.At.Format(time.RFC3339Nano))
	}
}

func TestCwdObservationPreservesExplicitUnknownStatus(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-command-unknown"), map[string]any{
		"eventid": "cowrie.command.input", "session": "session-1",
		"cwd": "/home/operator", "cwd_status": "unknown",
	})
	if !ok || observation.Status != "unknown" {
		t.Fatalf("explicit producer confidence must not be upgraded: %#v", observation)
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

func TestCwdObservationFromChangePrefersContractCwdAfter(t *testing.T) {
	observation, ok := cwdObservationFromEvent(cwdEventForTest("raw-change-explicit"), map[string]any{
		"eventid": "cowrie.session.cwd", "session": "session-1",
		"cwd_before": "/home/operator", "cwd_after": "/var/tmp", "cwd": "/legacy",
		"cwd_action": "changed", "cwd_status": "confirmed",
	})
	if !ok || observation.Path != "/var/tmp" {
		t.Fatalf("explicit cwd_after must take precedence: %#v", observation)
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

func TestCwdStateOrderFilterRejectsOlderAndBreaksTimestampTies(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 123, time.UTC)
	filter := cwdStateOrderFilter(cwdObservation{
		SessionID: "session-1", SourceEventID: "event-b", At: at,
	})
	if filter["_id"] != "session-1" {
		t.Fatalf("filter is not scoped to the session: %#v", filter)
	}
	conditions, ok := filter["$or"].(bson.A)
	if !ok || len(conditions) != 3 {
		t.Fatalf("expected ordered and v1 migration conditions: %#v", filter)
	}
	tie, ok := conditions[1].(bson.M)
	if !ok || tie["stateSequence"] != at.UnixNano() {
		t.Fatalf("timestamp tie condition missing: %#v", conditions[1])
	}
	sourceOrder, ok := tie["stateSourceEventId"].(bson.M)
	if !ok || sourceOrder["$lt"] != "event-b" {
		t.Fatalf("source-event tie breaker missing: %#v", tie)
	}
}

func TestCwdStateDocumentStoresDateAndOrderMetadata(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 123, time.UTC)
	document := cwdStateDocument(cwdObservation{
		SessionID: "session-1", SourceIP: "198.51.100.7",
		SourceEventID: "event-b", At: at, Path: "/var/tmp", Status: "confirmed",
	}, 24*time.Hour)
	state, ok := document["cwdState"].(bson.M)
	if !ok || state["observedAt"] != at {
		t.Fatalf("state timestamp must remain a BSON date candidate: %#v", document)
	}
	if document["stateSequence"] != at.UnixNano() || document["stateSourceEventId"] != "event-b" {
		t.Fatalf("state order metadata missing: %#v", document)
	}
}

func TestCowrieCwdContractFixtures(t *testing.T) {
	contents, err := os.ReadFile("../../integrations/cowrie/fixtures/cwd-events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three producer contract fixtures, got %d", len(lines))
	}
	for index, line := range lines {
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("fixture %d is invalid JSON: %v", index, err)
		}
		if _, ok := cwdObservationFromEvent(cwdEventForTest("fixture-"+strconv.Itoa(index)), payload); !ok {
			t.Fatalf("fixture %d does not satisfy the processor contract: %#v", index, payload)
		}
	}
}
