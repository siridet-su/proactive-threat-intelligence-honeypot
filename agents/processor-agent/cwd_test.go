package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

func TestCwdSessionClosedRequiresCowrieLifecycleEvent(t *testing.T) {
	event := cwdEventForTest("session-closed")
	sessionID, closedAt, ok := cwdSessionClosedFromEvent(event, map[string]any{
		"eventid": "cowrie.session.closed", "session": "session-1",
	})
	if !ok || sessionID != "session-1" || closedAt.IsZero() {
		t.Fatalf("expected authoritative session close: id=%q at=%v ok=%v", sessionID, closedAt, ok)
	}
	if _, _, ok := cwdSessionClosedFromEvent(event, map[string]any{"eventid": "cowrie.session.closed"}); ok {
		t.Fatal("session close without a Cowrie session ID must be ignored")
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
	lifecycle, ok := filter["lifecycle.status"].(bson.M)
	if !ok || lifecycle["$ne"] != "closed" {
		t.Fatalf("closed sessions must reject late CWD updates: %#v", filter)
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
	lifecycle, ok := document["lifecycle"].(bson.M)
	if !ok || lifecycle["status"] != "active" || lifecycle["startedAt"] != at {
		t.Fatalf("active lifecycle metadata missing: %#v", document)
	}
}

func TestCwdSessionCloseUpdateCreatesRetentionBoundedTombstone(t *testing.T) {
	closedAt := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	update := cwdSessionCloseUpdate("session-1", closedAt, 24*time.Hour)
	if len(update) != 1 {
		t.Fatalf("close update must be a single generation-owning pipeline: %#v", update)
	}
	set, ok := update[0][0].Value.(bson.M)
	if !ok || set["lifecycle.status"] != "closed" || set["lifecycle.closedAt"] != closedAt {
		t.Fatalf("closed lifecycle state missing: %#v", update)
	}
	if set["expires_at"] != closedAt.Add(24*time.Hour) {
		t.Fatalf("close tombstone must retain only for the configured duration: %#v", update)
	}
	if set["auditProjectionPendingGeneration"] == nil || set["auditProjectionGeneration"] == nil {
		t.Fatalf("close tombstone generation metadata missing: %#v", update)
	}
}

func TestCowrieCwdContractFixtures(t *testing.T) {
	contents, err := os.ReadFile("../../integrations/cowrie/fixtures/cwd-events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected four producer contract fixtures, got %d", len(lines))
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

func TestCwdEventIndexesIncludeLegacySessionIdCompoundIndex(t *testing.T) {
	indexes := cwdEventIndexModels()
	hasCanonical := false
	hasLegacy := false
	hasPendingMarker := false

	for _, idx := range indexes {
		keys, ok := idx.Keys.(bson.D)
		if !ok {
			continue
		}
		if sameIndexKeys(keys, bson.D{{Key: "sessionId", Value: 1}, {Key: "at", Value: -1}, {Key: "eventId", Value: -1}}) {
			hasCanonical = true
		}
		if sameIndexKeys(keys, bson.D{{Key: "session_id", Value: 1}, {Key: "at", Value: -1}, {Key: "eventId", Value: -1}}) {
			hasLegacy = true
		}
		if sameIndexKeys(keys, bson.D{{Key: "auditProjectionPending", Value: 1}, {Key: "_id", Value: 1}}) {
			hasPendingMarker = true
		}
	}

	if !hasCanonical {
		t.Fatal("expected canonical sessionId compound index in cwd_events index models")
	}
	if !hasLegacy {
		t.Fatal("expected legacy session_id compound index in cwd_events index models to support mixed-schema rank aggregation")
	}
	if !hasPendingMarker {
		t.Fatal("expected indexed auditProjectionPending outbox marker")
	}
}

func TestCwdAuditProjectionIndexesBoundCanonicalAuditReadsAndTTL(t *testing.T) {
	indexes := cwdAuditProjectionIndexModels()
	want := []bson.D{
		{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}},
		{{Key: "lifecycle.status", Value: 1}, {Key: "auditHomeOnly", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}},
		{{Key: "lifecycle.status", Value: 1}, {Key: "auditVisitedPaths", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}},
		{{Key: "auditPathsOverflow", Value: 1}},
		{{Key: "expires_at", Value: 1}},
	}
	for _, expected := range want {
		found := false
		for _, index := range indexes {
			keys, ok := index.Keys.(bson.D)
			if ok && sameIndexKeys(keys, expected) {
				found = true
				if sameIndexKeys(expected, bson.D{{Key: "expires_at", Value: 1}}) {
					if index.Options == nil || index.Options.ExpireAfterSeconds == nil || *index.Options.ExpireAfterSeconds != 0 {
						t.Fatal("projection expires_at index must use expireAfterSeconds=0")
					}
				}
			}
		}
		if !found {
			t.Fatalf("missing projection index %#v", expected)
		}
	}

	legacyStateIndex := bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "session_id", Value: -1}}
	foundLegacy := false
	for _, index := range cwdStateIndexModels() {
		if keys, ok := index.Keys.(bson.D); ok && sameIndexKeys(keys, legacyStateIndex) {
			foundLegacy = true
		}
	}
	if !foundLegacy {
		t.Fatal("missing legacy session_id closed-time state index")
	}
}

func TestFA016MongoTargetRejectsUnsafeConfigurationsBeforeCallback(t *testing.T) {
	cases := []struct{ name, uri, database, runID string }{
		{"missing uri", "", "pti_fa016_test_abc", "abc"},
		{"missing db", "mongodb://127.0.0.1:27017/pti_fa016_test_abc", "", "abc"},
		{"missing run id", "mongodb://127.0.0.1:27017/pti_fa016_test_abc", "pti_fa016_test_abc", ""},
		{"uppercase run id", "mongodb://127.0.0.1:27017/pti_fa016_test_ABC", "pti_fa016_test_ABC", "ABC"},
		{"wrong prefix", "mongodb://127.0.0.1:27017/honeypot_db", "honeypot_db", "abc"},
		{"uri database mismatch", "mongodb://127.0.0.1:27017/pti_fa016_test_other", "pti_fa016_test_abc", "abc"},
		{"remote host", "mongodb://db.example/pti_fa016_test_abc", "pti_fa016_test_abc", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			if err := runWithValidatedFA016Target(tc.uri, tc.database, tc.runID, func(fa016MongoTarget) error { called = true; return nil }); err == nil {
				t.Fatal("unsafe target was accepted")
			}
			if called {
				t.Fatal("rejected target executed connection/destructive callback")
			}
		})
	}
}

func TestFA016MongoTargetAcceptsExactLoopbackTarget(t *testing.T) {
	target, err := validateFA016MongoTarget("mongodb://127.0.0.1:27017/pti_fa016_test_abc", "pti_fa016_test_abc", "abc")
	if err != nil || target.Database != "pti_fa016_test_abc" {
		t.Fatalf("valid target rejected: %#v %v", target, err)
	}
}

func TestTTLIndexCompatibilityRejectsNonTTLIndex(t *testing.T) {
	ttl := int32(0)
	wanted := mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}
	if indexOptionsCompatible(&existingIndex{Name: "expires_at_1"}, wanted) {
		t.Fatal("non-TTL index was accepted as the TTL contract")
	}
	if !indexOptionsCompatible(&existingIndex{Name: "expires_at_1", ExpireAfterSeconds: &ttl}, wanted) {
		t.Fatal("valid TTL index was rejected")
	}
}
