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
		"updatedAt":                        observation.At,
		"expires_at":                       expiryAt(observation.At, retention),
		"auditProjectionGeneration":        int64(1),
		"auditProjectionPendingGeneration": int64(1),
	}
}

func nextAuditProjectionGenerationExpression() bson.M {
	return bson.M{"$add": bson.A{bson.M{"$ifNull": bson.A{"$auditProjectionGeneration", int64(0)}}, int64(1)}}
}

func cwdStateUpdate(observation cwdObservation, retention time.Duration) mongo.Pipeline {
	document := cwdStateDocument(observation, retention)
	delete(document, "_id")
	nextGeneration := nextAuditProjectionGenerationExpression()
	return mongo.Pipeline{
		bson.D{{Key: "$set", Value: bson.M{
			"schemaVersion":      document["schemaVersion"],
			"sessionId":          document["sessionId"],
			"sourceIp":           document["sourceIp"],
			"stateSequence":      document["stateSequence"],
			"stateSourceEventId": document["stateSourceEventId"],
			"cwdState":           document["cwdState"],
			// cwdStateOrderFilter rejects a closed state, so an authoritative CWD
			// observation can safely activate a legacy projection that predates
			// lifecycle metadata without reviving a closed session.
			"lifecycle.status":                 "active",
			"updatedAt":                        document["updatedAt"],
			"expires_at":                       document["expires_at"],
			"auditProjectionGeneration":        nextGeneration,
			"auditProjectionPendingGeneration": nextGeneration,
		}}},
		bson.D{{Key: "$set", Value: bson.M{
			// Preserve the actual first CWD observation, while giving legacy
			// documents lifecycle metadata the first time they receive v2 telemetry.
			"lifecycle.startedAt": bson.M{"$cond": bson.A{
				bson.M{"$or": bson.A{
					bson.M{"$eq": bson.A{bson.M{"$type": "$lifecycle.startedAt"}, "missing"}},
					bson.M{"$eq": bson.A{"$lifecycle.startedAt", nil}},
					bson.M{"$gt": bson.A{"$lifecycle.startedAt", observation.At}},
				}},
				observation.At,
				"$lifecycle.startedAt",
			}},
		}}},
	}
}

func cwdSessionCloseUpdate(sessionID string, closedAt time.Time, retention time.Duration) mongo.Pipeline {
	nextGeneration := nextAuditProjectionGenerationExpression()
	return mongo.Pipeline{bson.D{{Key: "$set", Value: bson.M{
		"schemaVersion":                    cwdStateSchemaVersion,
		"sessionId":                        sessionID,
		"lifecycle.status":                 "closed",
		"lifecycle.closedAt":               closedAt,
		"updatedAt":                        closedAt,
		"expires_at":                       expiryAt(closedAt, retention),
		"auditProjectionGeneration":        nextGeneration,
		"auditProjectionPendingGeneration": nextGeneration,
	}}}}
}

type cwdProjectionWork struct {
	accepted   bool
	sourceID   any
	generation int64
}

func projectionWorkFromState(state bson.M, accepted bool) cwdProjectionWork {
	return cwdProjectionWork{accepted: accepted, sourceID: state["_id"], generation: bsonInt64(state["auditProjectionGeneration"])}
}

func (mw *MongoWriter) closeCwdSession(ctx context.Context, sessionID string, closedAt time.Time, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to close CWD session")
	}
	states := mw.db.Collection("cwd_session_state")
	result, err := states.UpdateOne(
		ctx,
		// The first close establishes the retention boundary. A retried close
		// must be a harmless no-op rather than changing an already closed row.
		bson.M{"_id": sessionID, "lifecycle.status": bson.M{"$ne": "closed"}},
		cwdSessionCloseUpdate(sessionID, closedAt, retention),
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		var existing bson.M
		findErr := states.FindOne(ctx, bson.M{"_id": sessionID}).Decode(&existing)
		if findErr == mongo.ErrNoDocuments {
			_, err = states.UpdateOne(ctx, bson.M{"_id": sessionID, "lifecycle.status": bson.M{"$ne": "closed"}}, cwdSessionCloseUpdate(sessionID, closedAt, retention), options.Update().SetUpsert(true))
			if err != nil && !mongo.IsDuplicateKeyError(err) {
				return err
			}
		} else if findErr != nil {
			return findErr
		}
	}
	var state bson.M
	if err := states.FindOne(ctx, bson.M{"_id": sessionID}).Decode(&state); err != nil {
		return err
	}
	if mw.auditAfterCwdCloseStateUpdate != nil {
		mw.auditAfterCwdCloseStateUpdate()
	}
	return mw.closeCwdAuditProjection(ctx, state["_id"], sessionID, bsonInt64(state["auditProjectionGeneration"]), closedAt, retention)
}

// updateLatestCwdState performs a compare-and-set without a read/write race.
// Update-first handles existing sessions; insert-then-retry handles concurrent
// first observations without allowing a stale observation to win permanently.
func updateLatestCwdState(ctx context.Context, states *mongo.Collection, observation cwdObservation, retention time.Duration) (cwdProjectionWork, error) {
	filter := cwdStateOrderFilter(observation)
	update := cwdStateUpdate(observation, retention)
	var updated bson.M
	err := states.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updated)
	if err == mongo.ErrNoDocuments {
		err = nil
	}
	if err != nil {
		return cwdProjectionWork{}, err
	}
	if updated != nil {
		return projectionWorkFromState(updated, true), nil
	}

	if _, err := states.InsertOne(ctx, cwdStateDocument(observation, retention)); err == nil {
		var inserted bson.M
		if err := states.FindOne(ctx, bson.M{"_id": observation.SessionID}).Decode(&inserted); err != nil {
			return cwdProjectionWork{}, err
		}
		return projectionWorkFromState(inserted, true), nil
	} else if !mongo.IsDuplicateKeyError(err) {
		return cwdProjectionWork{}, err
	}

	// Another worker inserted the session between UpdateOne and InsertOne. A
	// final ordered update makes the newer observation win; zero matches means
	// this observation is stale and is intentionally ignored.
	updated = nil
	err = states.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updated)
	if err == mongo.ErrNoDocuments {
		var current bson.M
		if findErr := states.FindOne(ctx, bson.M{"_id": observation.SessionID}).Decode(&current); findErr != nil {
			return cwdProjectionWork{}, findErr
		}
		return projectionWorkFromState(current, false), nil
	}
	if err != nil {
		return cwdProjectionWork{}, err
	}
	return projectionWorkFromState(updated, true), nil
}

func (mw *MongoWriter) recordCwdObservation(ctx context.Context, observation cwdObservation, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to acknowledge CWD telemetry")
	}

	stateWork, err := updateLatestCwdState(ctx, mw.db.Collection("cwd_session_state"), observation, retention)
	if err != nil {
		return fmt.Errorf("update CWD state: %w", err)
	}
	if mw.auditAfterCwdStateUpdate != nil {
		mw.auditAfterCwdStateUpdate()
	}

	// Command observations update only current state. History is reserved for
	// Cowrie-emitted transitions so the audit trail never infers cd semantics
	// from attacker-controlled command text or cross-event state changes.
	if observation.Action == "observed" {
		// A rejected observed payload did not own a state generation. It must not
		// seed facts or acknowledge another writer's pending work.
		if !stateWork.accepted {
			return nil
		}
		if err := mw.updateCwdAuditProjection(ctx, observation, stateWork.sourceID, stateWork.generation, "", stateWork.accepted, retention); err != nil {
			return fmt.Errorf("update CWD audit projection: %w", err)
		}
		return nil
	}
	if stateWork.accepted {
		// Current-state ownership and history ownership are separate writes. The
		// state projection may become ready before the event outbox is committed;
		// neither application is allowed to suppress the other by generation.
		if err := mw.updateCwdAuditProjection(ctx, observation, stateWork.sourceID, stateWork.generation, "", true, retention); err != nil {
			return fmt.Errorf("update CWD current projection: %w", err)
		}
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
		"sequence": strconv.FormatInt(observation.At.UnixNano(), 10),
		"fromPath": observation.FromPath,
		"toPath":   eventToPath,
		"action":   observation.Action,
		"status":   observation.Status,
		// The event itself is the durable reconciliation outbox. This marker is
		// written atomically with cwd_events, so a writer cannot commit history
		// and then crash before leaving discoverable projection work.
		"auditProjectionPending": true,
		"expires_at":             expiryAt(observation.At, retention),
	}
	// Establish the generation-owned pending marker before the durable history
	// write. This closes the non-transactional crash window for stale events.
	eventWork, err := mw.advanceCwdProjectionGenerationForEvent(ctx, stateWork.sourceID, true)
	if err != nil {
		return fmt.Errorf("mark CWD history projection pending: %w", err)
	}
	if mw.auditAfterCwdEventPending != nil {
		mw.auditAfterCwdEventPending()
	}
	_, err = mw.db.Collection("cwd_events").UpdateOne(
		ctx, bson.M{"_id": eventID}, bson.M{"$setOnInsert": event}, options.Update().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("upsert CWD event: %w", err)
	}
	if mw.auditAfterCwdEventWrite != nil {
		mw.auditAfterCwdEventWrite()
	}
	if err := mw.updateCwdAuditProjection(ctx, observation, eventWork.sourceID, eventWork.generation, eventID, stateWork.accepted, retention); err != nil {
		return fmt.Errorf("update CWD audit projection: %w", err)
	}
	return nil
}

// cwdEventIndexModels returns the MongoDB indexes provisioned for cwd_events.
// Both canonical sessionId and legacy session_id compound indexes are defined
// so mixed-schema rank aggregations ($or: [{ sessionId }, { session_id }])
// execute via index-union IXSCAN without falling back to collection scans.
func cwdEventIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{Keys: bson.D{{Key: "sessionId", Value: 1}, {Key: "at", Value: -1}, {Key: "eventId", Value: -1}}},
		{Keys: bson.D{{Key: "session_id", Value: 1}, {Key: "at", Value: -1}, {Key: "eventId", Value: -1}}},
		{Keys: bson.D{{Key: "auditProjectionPending", Value: 1}, {Key: "sessionId", Value: 1}}},
		{Keys: bson.D{{Key: "auditProjectionPending", Value: 1}, {Key: "session_id", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
}
