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

// cwdSessionClosedFromEvent accepts only Cowrie's session lifecycle event. It
// is intentionally separate from CWD observations: closing a session must not
// invent a directory transition or add an audit-history entry.
func cwdSessionClosedFromEvent(event map[string]any, payload map[string]any) (string, time.Time, bool) {
	if getNestedString(event, "source") != "cowrie" || getPayloadString(payload, "eventid") != "cowrie.session.closed" {
		return "", time.Time{}, false
	}
	sessionID := cleanText(getPayloadString(payload, "session"))
	if sessionID == "" {
		return "", time.Time{}, false
	}
	at, ok := cwdObservationTimestamp(event)
	if !ok {
		return "", time.Time{}, false
	}
	return sessionID, at, true
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

	observedAt, ok := cwdObservationTimestamp(event)
	if !ok {
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

// cwdObservationTimestamp accepts the native timestamp produced by
// normalizeEvent and the RFC3339 string produced when enrichEvent deep-copies
// that event through JSON. Both forms represent the same source timestamp.
func cwdObservationTimestamp(event map[string]any) (time.Time, bool) {
	switch timestamp := event["timestamp"].(type) {
	case time.Time:
		if timestamp.IsZero() {
			return time.Time{}, false
		}
		return timestamp.UTC(), true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(timestamp))
		if err != nil || parsed.IsZero() {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	default:
		return time.Time{}, false
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
		// A late/retried CWD event must never revive a session that Cowrie has
		// already closed. Older v2 documents without lifecycle metadata remain
		// eligible for their first lifecycle-aware update.
		"lifecycle.status": bson.M{"$ne": "closed"},
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
		"lifecycle": bson.M{
			"status":    "active",
			"startedAt": observation.At,
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
			// cwdStateOrderFilter rejects a closed state, so an authoritative CWD
			// observation can safely activate a legacy projection that predates
			// lifecycle metadata without reviving a closed session.
			"lifecycle.status": "active",
			"updatedAt":        document["updatedAt"],
			"expires_at":       document["expires_at"],
		},
		// Preserve the actual first CWD observation, while giving legacy
		// documents lifecycle metadata the first time they receive v2 telemetry.
		"$min": bson.M{"lifecycle.startedAt": observation.At},
	}
}

func cwdSessionCloseUpdate(sessionID string, closedAt time.Time, retention time.Duration) bson.M {
	return bson.M{
		"$set": bson.M{
			"lifecycle.status":   "closed",
			"lifecycle.closedAt": closedAt,
			"updatedAt":          closedAt,
			"expires_at":         expiryAt(closedAt, retention),
		},
		// A close can be observed before an initial CWD event reaches this
		// consumer. The tombstone makes that ordering safe: a later CWD insert
		// hits the duplicate key path and is rejected by cwdStateOrderFilter.
		"$setOnInsert": bson.M{
			"schemaVersion": cwdStateSchemaVersion,
			"sessionId":     sessionID,
		},
	}
}

func (mw *MongoWriter) closeCwdSession(ctx context.Context, sessionID string, closedAt time.Time, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to close CWD session")
	}
	_, err := mw.db.Collection("cwd_session_state").UpdateOne(
		ctx,
		// Do not filter out an already closed document here: the raw Redis
		// stream is at-least-once, so a retried close must be a harmless update
		// rather than an upsert attempt that collides with the existing _id.
		bson.M{"_id": sessionID},
		cwdSessionCloseUpdate(sessionID, closedAt, retention),
		options.Update().SetUpsert(true),
	)
	return err
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
