package main

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	cwdEventSchemaVersion = "cwd_event.v1"
	cwdStateSchemaVersion = "cwd_session_state.v1"
)

type cwdObservation struct {
	SessionID     string
	SourceIP      string
	SourceEventID string
	At            time.Time
	Path          string
	FromPath      string
	Action        string
	Status        string
}

// cwdObservationFromEvent accepts only fields produced by Cowrie itself. It
// deliberately does not parse an attacker's command text to simulate a shell.
func cwdObservationFromEvent(event map[string]any, payload map[string]any) (cwdObservation, bool) {
	if getNestedString(event, "source") != "cowrie" {
		return cwdObservation{}, false
	}

	sessionID := cleanText(getPayloadString(payload, "session"))
	sourceEventID := cleanText(getNestedString(event, "event_id"))
	if sessionID == "" || sourceEventID == "" {
		return cwdObservation{}, false
	}

	observedAt, ok := event["timestamp"].(time.Time)
	if !ok || observedAt.IsZero() {
		return cwdObservation{}, false
	}
	base := cwdObservation{
		SessionID: sessionID, SourceIP: cleanText(getNestedString(event, "network.src_ip")),
		SourceEventID: sourceEventID, At: observedAt.UTC(),
	}

	switch getPayloadString(payload, "eventid") {
	case "cowrie.command.input":
		cwd := canonicalCwd(getPayloadString(payload, "cwd_before"))
		if cwd == "" {
			return cwdObservation{}, false
		}
		base.Path, base.Action, base.Status = cwd, "observed", "observed"
		return base, true
	case "cowrie.session.cwd":
		base.Action = cwdAction(getPayloadString(payload, "cwd_action"))
		base.Status = cwdStatus(getPayloadString(payload, "cwd_status"))
		base.FromPath = canonicalCwd(getPayloadString(payload, "cwd_before"))
		base.Path = canonicalCwd(firstNonEmpty(
			getPayloadString(payload, "cwd"), getPayloadString(payload, "cwd_after"),
		))
		if base.Action == "failed_change" {
			// A failed cd retains Cowrie's known previous directory; never store a
			// target path that might only be an attacker-supplied argument.
			base.Path = base.FromPath
			if base.Status == "unknown" {
				base.Status = "observed"
			}
		}
		if base.Path == "" {
			return cwdObservation{}, false
		}
		return base, true
	default:
		return cwdObservation{}, false
	}
}

func canonicalCwd(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') || !strings.HasPrefix(value, "/") {
		return ""
	}
	// Cowrie resolves its virtual filesystem before emitting the field. Reject a
	// non-canonical representation rather than silently rewriting evidence.
	if path.Clean(value) != value {
		return ""
	}
	return value
}

func cwdAction(value string) string {
	switch strings.TrimSpace(value) {
	case "entered", "changed", "failed_change":
		return strings.TrimSpace(value)
	default:
		return "changed"
	}
}

func cwdStatus(value string) string {
	switch strings.TrimSpace(value) {
	case "observed", "confirmed", "conditional_candidate", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func cleanText(value string) string { return strings.TrimSpace(value) }

func statusRank(status string) int {
	switch status {
	case "confirmed":
		return 3
	case "observed":
		return 2
	case "conditional_candidate":
		return 1
	default:
		return 0
	}
}

func statePath(document bson.M) (string, string) {
	state, _ := document["cwdState"].(bson.M)
	if state == nil {
		if mapped, ok := document["cwdState"].(map[string]any); ok {
			return cleanText(valueToString(mapped["path"])), cleanText(valueToString(mapped["status"]))
		}
		return "", ""
	}
	return cleanText(valueToString(state["path"])), cleanText(valueToString(state["status"]))
}

func (mw *MongoWriter) recordCwdObservation(ctx context.Context, observation cwdObservation, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to acknowledge CWD telemetry")
	}

	states := mw.db.Collection("cwd_session_state")
	var previous bson.M
	err := states.FindOne(ctx, bson.M{"_id": observation.SessionID}).Decode(&previous)
	if err != nil && err != mongo.ErrNoDocuments {
		return fmt.Errorf("read CWD state: %w", err)
	}
	previousPath, previousStatus := statePath(previous)

	action := observation.Action
	eventFromPath := observation.FromPath
	eventToPath := observation.Path
	shouldRecord := action != "observed"
	if action == "observed" && observation.Path != previousPath {
		shouldRecord = true
		if previousPath == "" {
			action = "entered"
		} else {
			action = "changed"
			eventFromPath = previousPath
		}
	}
	if action == "failed_change" {
		eventToPath = ""
	}

	stateStatus := observation.Status
	if previousPath == observation.Path && statusRank(previousStatus) > statusRank(stateStatus) {
		stateStatus = previousStatus
	}
	state := bson.M{
		"path":          observation.Path,
		"status":        stateStatus,
		"observedAt":    observation.At.Format(time.RFC3339Nano),
		"sourceEventId": observation.SourceEventID,
	}
	stateUpdate := bson.M{
		"$set": bson.M{
			"sessionId":  observation.SessionID,
			"sourceIp":   observation.SourceIP,
			"cwdState":   state,
			"updatedAt":  observation.At,
			"expires_at": expiryAt(observation.At, retention),
		},
		"$setOnInsert": bson.M{"schemaVersion": cwdStateSchemaVersion},
	}
	if _, err := states.UpdateOne(ctx, bson.M{"_id": observation.SessionID}, stateUpdate, options.Update().SetUpsert(true)); err != nil {
		return fmt.Errorf("update CWD state: %w", err)
	}

	if !shouldRecord {
		return nil
	}

	eventID := "cwd:" + observation.SourceEventID
	event := bson.M{
		"_id":           eventID,
		"schemaVersion": cwdEventSchemaVersion,
		"eventId":       eventID,
		"sourceEventId": observation.SourceEventID,
		"sessionId":     observation.SessionID,
		"at":            observation.At,
		// Nanoseconds are a stable ordering key derived from the observed source
		// timestamp; sourceEventId remains the idempotency key for ties.
		"sequence":   observation.At.UnixNano(),
		"fromPath":   eventFromPath,
		"toPath":     eventToPath,
		"action":     action,
		"status":     observation.Status,
		"expires_at": expiryAt(observation.At, retention),
	}
	if _, err := mw.db.Collection("cwd_events").UpdateOne(
		ctx, bson.M{"_id": eventID}, bson.M{"$setOnInsert": event}, options.Update().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("upsert CWD event: %w", err)
	}
	return nil
}
