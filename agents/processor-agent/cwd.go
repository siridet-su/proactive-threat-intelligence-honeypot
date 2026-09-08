package main

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	cwdEventSchemaVersion = "cwd_event.v2"
	cwdStateSchemaVersion = "cwd_session_state.v2"
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
		// The reviewed Cowrie patch emits cwd directly from protocol.cwd before
		// command execution. cwd_before remains accepted for the original draft
		// contract, but command text is never parsed as a fallback.
		directCwd := canonicalCwd(getPayloadString(payload, "cwd"))
		cwd := directCwd
		if cwd == "" {
			cwd = canonicalCwd(getPayloadString(payload, "cwd_before"))
		}
		if cwd == "" {
			return cwdObservation{}, false
		}
		rawStatus := cleanText(getPayloadString(payload, "cwd_status"))
		status := cwdStatus(rawStatus)
		if rawStatus == "" {
			if directCwd != "" {
				status = "confirmed"
			} else {
				status = "observed"
			}
		}
		base.Path, base.Action, base.Status = cwd, "observed", status
		return base, true
	case "cowrie.session.cwd":
		base.Action = cwdAction(getPayloadString(payload, "cwd_action"))
		rawStatus := cleanText(getPayloadString(payload, "cwd_status"))
		base.Status = cwdStatus(rawStatus)
		base.FromPath = canonicalCwd(getPayloadString(payload, "cwd_before"))
		base.Path = canonicalCwd(firstNonEmpty(
			getPayloadString(payload, "cwd_after"), getPayloadString(payload, "cwd"),
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

func cwdStateOrderFilter(observation cwdObservation) bson.M {
	sequence := observation.At.UnixNano()
	return bson.M{
		"_id": observation.SessionID,
		"$or": bson.A{
			bson.M{"stateSequence": bson.M{"$lt": sequence}},
			bson.M{
				"stateSequence":      sequence,
				"stateSourceEventId": bson.M{"$lt": observation.SourceEventID},
			},
			// Documents written by cwd_session_state.v1 did not have an order
			// key. Allow one v2 observation to migrate them in place.
			bson.M{"stateSequence": bson.M{"$exists": false}},
		},
	}
}

func cwdStateDocument(observation cwdObservation, retention time.Duration) bson.M {
	return bson.M{
		"_id":                observation.SessionID,
		"schemaVersion":      cwdStateSchemaVersion,
		"sessionId":          observation.SessionID,
		"sourceIp":           observation.SourceIP,
		"stateSequence":      observation.At.UnixNano(),
		"stateSourceEventId": observation.SourceEventID,
		"cwdState": bson.M{
			"path":          observation.Path,
			"status":        observation.Status,
			"observedAt":    observation.At,
			"sourceEventId": observation.SourceEventID,
		},
		"updatedAt":  observation.At,
		"expires_at": expiryAt(observation.At, retention),
	}
}

func cwdStateUpdate(observation cwdObservation, retention time.Duration) bson.M {
	document := cwdStateDocument(observation, retention)
	delete(document, "_id")
	return bson.M{
		"$set": bson.M{
			"schemaVersion":      document["schemaVersion"],
			"sessionId":          document["sessionId"],
			"sourceIp":           document["sourceIp"],
			"stateSequence":      document["stateSequence"],
			"stateSourceEventId": document["stateSourceEventId"],
			"cwdState":           document["cwdState"],
			"updatedAt":          document["updatedAt"],
			"expires_at":         document["expires_at"],
		},
	}
}

// updateLatestCwdState performs a compare-and-set without a read/write race.
// Update-first handles existing sessions; insert-then-retry handles concurrent
// first observations without allowing a stale observation to win permanently.
func updateLatestCwdState(ctx context.Context, states *mongo.Collection, observation cwdObservation, retention time.Duration) error {
	filter := cwdStateOrderFilter(observation)
	update := cwdStateUpdate(observation, retention)
	result, err := states.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount > 0 {
		return nil
	}

	if _, err := states.InsertOne(ctx, cwdStateDocument(observation, retention)); err == nil {
		return nil
	} else if !mongo.IsDuplicateKeyError(err) {
		return err
	}

	// Another worker inserted the session between UpdateOne and InsertOne. A
	// final ordered update makes the newer observation win; zero matches means
	// this observation is stale and is intentionally ignored.
	_, err = states.UpdateOne(ctx, filter, update)
	return err
}

func (mw *MongoWriter) recordCwdObservation(ctx context.Context, observation cwdObservation, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to acknowledge CWD telemetry")
	}

	if err := updateLatestCwdState(ctx, mw.db.Collection("cwd_session_state"), observation, retention); err != nil {
		return fmt.Errorf("update CWD state: %w", err)
	}

	// Command observations update only current state. History is reserved for
	// Cowrie-emitted transitions so the audit trail never infers cd semantics
	// from attacker-controlled command text or cross-event state changes.
	if observation.Action == "observed" {
		return nil
	}

	eventID := "cwd:" + observation.SourceEventID
	eventToPath := observation.Path
	if observation.Action == "failed_change" {
		eventToPath = ""
	}
	event := bson.M{
		"_id":           eventID,
		"schemaVersion": cwdEventSchemaVersion,
		"eventId":       eventID,
		"sourceEventId": observation.SourceEventID,
		"sessionId":     observation.SessionID,
		"at":            observation.At,
		// Keep the nanosecond sequence as a decimal string. JavaScript cannot
		// represent current Unix nanoseconds safely as a Number.
		"sequence":   strconv.FormatInt(observation.At.UnixNano(), 10),
		"fromPath":   observation.FromPath,
		"toPath":     eventToPath,
		"action":     observation.Action,
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
