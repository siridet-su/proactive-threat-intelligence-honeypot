package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	cwdAuditProjectionCollection      = "cwd_audit_projection"
	cwdAuditProjectionVersion         = "cwd_audit_projection.v2"
	cwdAuditProjectionMetaID          = "audit-directory"
	cwdAuditProjectionRepairBatchSize = 256
	// A projection remains a bounded page/read accelerator. If a session has
	// more distinct transition paths, the overflow bit forces authoritative
	// source fallback for exact filters/summary while keeping this document
	// well below MongoDB's 16 MB limit.
	cwdAuditProjectionMaxPaths = 512
)

// The projection is a database-owned read model. cwd_session_state and
// cwd_events remain the source records; this collection stores only facts
// needed by the retained Audit directory and is rebuilt/converged by the
// processor. sessionId is always canonical here, even when the source state
// used session_id.
func cwdAuditProjectionIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditHomeOnly", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditVisitedPaths", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "auditPathsOverflow", Value: 1}}},
		// Projection expiry is an indexed cleanup watermark, not an independent
		// TTL. cwd_session_state owns retention; cleanup removes this row only
		// after the source row is gone.
		{Keys: bson.D{{Key: "expires_at", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}, {Key: "_id", Value: 1}}},
	}
}

func cwdStateIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "updatedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "session_id", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditProjectionVersion", Value: 1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditProjectionPendingGeneration", Value: 1}}, Options: options.Index().SetPartialFilterExpression(bson.M{"auditProjectionPendingGeneration": bson.M{"$exists": true}})},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "sessionId", Value: 1}, {Key: "_id", Value: 1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "session_id", Value: 1}, {Key: "_id", Value: 1}}},
		{Keys: bson.D{{Key: "auditCanonicalSessionId", Value: 1}}},
		{Keys: bson.D{{Key: "sessionId", Value: 1}}},
		{Keys: bson.D{{Key: "session_id", Value: 1}}},
		{Keys: bson.D{{Key: "cwdState.path", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
}

func auditProjectionPathSetExpression(field string, paths ...string) bson.D {
	values := bson.A{}
	for _, path := range paths {
		values = append(values, path)
	}
	raw := bson.D{{Key: "$setUnion", Value: bson.A{
		bson.D{{Key: "$ifNull", Value: bson.A{field, bson.A{}}}},
		values,
	}}}
	return bson.D{{Key: "$filter", Value: bson.D{
		{Key: "input", Value: raw},
		{Key: "as", Value: "path"},
		{Key: "cond", Value: bson.D{{Key: "$and", Value: bson.A{
			bson.D{{Key: "$ne", Value: bson.A{"$$path", nil}}},
			bson.D{{Key: "$ne", Value: bson.A{"$$path", ""}}},
			bson.D{{Key: "$regexMatch", Value: bson.D{{Key: "input", Value: "$$path"}, {Key: "regex", Value: "^/"}}}},
		}}}},
	}}}
}

func auditProjectionVisitedPathsExpression() bson.D {
	currentPath := bson.D{{Key: "$map", Value: bson.D{{Key: "input", Value: bson.A{1}}, {Key: "as", Value: "ignored"}, {Key: "in", Value: "$cwdState.path"}}}}
	return auditProjectionVisitedPathsWithCurrentPath(currentPath)
}

func auditProjectionVisitedPathsWithCurrentPath(currentPath bson.D) bson.D {
	return bson.D{{Key: "$filter", Value: bson.D{{Key: "input", Value: bson.D{{Key: "$setUnion", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$auditTransitionPaths", bson.A{}}}}, currentPath}}}}, {Key: "as", Value: "path"}, {Key: "cond", Value: bson.D{{Key: "$and", Value: bson.A{bson.D{{Key: "$ne", Value: bson.A{"$$path", nil}}}, bson.D{{Key: "$ne", Value: bson.A{"$$path", ""}}}, bson.D{{Key: "$regexMatch", Value: bson.D{{Key: "input", Value: "$$path"}, {Key: "regex", Value: "^/"}}}}}}}}}}}
}

func auditProjectionBoundedPathsExpression(paths bson.D) bson.D {
	return bson.D{{Key: "$slice", Value: bson.A{paths, cwdAuditProjectionMaxPaths}}}
}

func auditProjectionOverflowExpression(paths bson.D) bson.D {
	return bson.D{{Key: "$gt", Value: bson.A{bson.D{{Key: "$size", Value: paths}}, cwdAuditProjectionMaxPaths}}}
}

func auditProjectionHomeOnlyExpression(paths any) bson.D {
	nonRoot := bson.M{
		"$filter": bson.M{
			"input": paths,
			"as":    "p",
			"cond":  bson.M{"$ne": bson.A{"$$p", "/"}},
		},
	}
	hasHome := bson.M{
		"$anyElementTrue": bson.M{
			"$map": bson.M{
				"input": nonRoot,
				"as":    "p",
				"in": bson.M{
					"$or": bson.A{
						bson.M{"$eq": bson.A{"$$p", "/home"}},
						bson.M{"$regexMatch": bson.M{"input": "$$p", "regex": "^/home/"}},
					},
				},
			},
		},
	}
	hasOutside := bson.M{
		"$anyElementTrue": bson.M{
			"$map": bson.M{
				"input": nonRoot,
				"as":    "p",
				"in": bson.M{
					"$and": bson.A{
						bson.M{"$ne": bson.A{"$$p", "/home"}},
						bson.M{"$not": bson.M{"$regexMatch": bson.M{"input": "$$p", "regex": "^/home/"}}},
					},
				},
			},
		},
	}
	return bson.D{
		{Key: "$and", Value: bson.A{hasHome, bson.M{"$not": hasOutside}}},
	}
}

func auditProjectionCurrentStateUpdate(observation cwdObservation, generation int64, changed bool, retention time.Duration) mongo.Pipeline {
	if !changed {
		return nil
	}
	currentPath := bson.D{{Key: "$map", Value: bson.D{{Key: "input", Value: bson.A{1}}, {Key: "as", Value: "ignored"}, {Key: "in", Value: observation.Path}}}}
	paths := auditProjectionVisitedPathsWithCurrentPath(currentPath)
	stage := bson.D{{Key: "$set", Value: bson.D{
		{Key: "sessionId", Value: observation.SessionID},
		{Key: "sourceIp", Value: observation.SourceIP},
		{Key: "stateSequence", Value: observation.At.UnixNano()},
		{Key: "stateSourceEventId", Value: observation.SourceEventID},
		{Key: "cwdState", Value: bson.D{
			{Key: "path", Value: observation.Path},
			{Key: "status", Value: observation.Status},
			{Key: "observedAt", Value: observation.At},
			{Key: "sourceEventId", Value: observation.SourceEventID},
		}},
		{Key: "auditVisitedPaths", Value: paths},
		{Key: "auditHomeOnly", Value: auditProjectionHomeOnlyExpression(paths)},
		{Key: "expires_at", Value: expiryAt(observation.At, retention)},
		{Key: "auditProjectionVersion", Value: cwdAuditProjectionVersion},
		{Key: "auditProjectionGeneration", Value: generation},
		{Key: "updatedAt", Value: time.Now().UTC()},
	}}}
	return mongo.Pipeline{stage, bson.D{{Key: "$unset", Value: bson.A{"auditEventIds", "visitedPaths", "eventCount", "homeOnly"}}}}
}

func auditProjectionStateOrderFilter(observation cwdObservation) bson.M {
	return bson.M{
		"_id":              observation.SessionID,
		"lifecycle.status": bson.M{"$ne": "closed"},
		"$or": bson.A{
			bson.M{"stateSequence": bson.M{"$lt": observation.At.UnixNano()}},
			bson.M{"stateSequence": observation.At.UnixNano(), "stateSourceEventId": bson.M{"$lt": observation.SourceEventID}},
			bson.M{"stateSequence": bson.M{"$exists": false}},
		},
	}
}

func (mw *MongoWriter) seedCwdAuditProjection(ctx context.Context, observation cwdObservation, generation int64, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to seed CWD audit projection")
	}
	seed := bson.M{
		"schemaVersion":             cwdAuditProjectionVersion,
		"sessionId":                 observation.SessionID,
		"sourceIp":                  observation.SourceIP,
		"cwdState":                  bson.M{"path": observation.Path, "status": observation.Status, "observedAt": observation.At, "sourceEventId": observation.SourceEventID},
		"auditTransitionPaths":      bson.A{},
		"auditVisitedPaths":         bson.A{observation.Path},
		"auditPathsOverflow":        false,
		"auditEventCount":           0,
		"auditHistoryRevision":      int64(0),
		"auditHomeOnly":             false,
		"auditProjectionVersion":    cwdAuditProjectionVersion,
		"auditProjectionGeneration": generation,
		"stateSequence":             observation.At.UnixNano(),
		"stateSourceEventId":        observation.SourceEventID,
		"lifecycle":                 bson.M{"status": "active", "startedAt": observation.At},
		"updatedAt":                 observation.At,
		"expires_at":                expiryAt(observation.At, retention),
	}
	// A close-before-history ordering must not be turned back into an active
	// projection. The close handler normally creates this row first; this read
	// protects the crash/retry window between the two collection writes.
	var state bson.M
	err := mw.db.Collection("cwd_session_state").FindOne(ctx, bson.M{"$or": bson.A{
		bson.M{"_id": observation.SessionID},
		bson.M{"sessionId": observation.SessionID},
		bson.M{"session_id": observation.SessionID},
	}}).Decode(&state)
	if err == nil {
		if lifecycle, ok := state["lifecycle"].(bson.M); ok {
			if status, _ := lifecycle["status"].(string); status == "closed" {
				seed["lifecycle"] = lifecycle
			}
		}
		if expires, ok := state["expires_at"]; ok {
			seed["expires_at"] = expires
		}
	} else if err != mongo.ErrNoDocuments {
		return err
	}
	_, err = mw.db.Collection(cwdAuditProjectionCollection).UpdateOne(
		ctx,
		bson.M{"_id": observation.SessionID},
		bson.M{"$setOnInsert": seed},
		options.Update().SetUpsert(true),
	)
	if err != nil && !mongo.IsDuplicateKeyError(err) {
		return err
	}
	return nil
}

func (mw *MongoWriter) updateCwdAuditProjection(ctx context.Context, observation cwdObservation, sourceID any, generation int64, eventID string, changed bool, retention time.Duration) error {
	if eventID != "" {
		// History is rebuilt from the durable event collection. The event's
		// pending bit remains set until this authoritative pass has actually
		// matched the projection, so a close or another writer cannot hide a
		// late event that commits after its original generation was superseded.
		converged, err := mw.backfillCwdAuditProjectionSessionResult(ctx, observation.SessionID, retention)
		if err != nil {
			return err
		}
		if converged {
			if _, err := mw.clearCwdEventProjectionWork(ctx, eventID); err != nil {
				return err
			}
		}
		return nil
	}
	if !changed {
		return nil
	}
	if err := mw.seedCwdAuditProjection(ctx, observation, generation, retention); err != nil {
		return err
	}
	collection := mw.db.Collection(cwdAuditProjectionCollection)
	if _, err := collection.UpdateOne(ctx, auditProjectionStateOrderFilter(observation), auditProjectionCurrentStateUpdate(observation, generation, true, retention)); err != nil {
		return err
	}
	return mw.markCwdAuditSourceReady(ctx, sourceID, generation)
}

func (mw *MongoWriter) markCwdAuditSourceReady(ctx context.Context, sourceID any, generation int64) error {
	result, err := mw.db.Collection("cwd_session_state").UpdateOne(ctx, bson.M{
		"_id":                              sourceID,
		"auditProjectionGeneration":        generation,
		"auditProjectionPendingGeneration": generation,
	}, bson.M{
		"$set": bson.M{
			"auditProjectionVersion":         cwdAuditProjectionVersion,
			"auditProjectionReadyGeneration": generation,
		},
		"$unset": bson.M{
			"auditProjectionPendingGeneration": "",
			"auditProjectionDirty":             "",
			"auditProjectionPendingEventCount": "",
		},
	})
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return nil
	}
	return nil
}

func (mw *MongoWriter) clearCwdEventProjectionWork(ctx context.Context, eventID string) (bool, error) {
	result, err := mw.db.Collection("cwd_events").UpdateOne(ctx, bson.M{"_id": eventID, "auditProjectionPending": true}, bson.M{"$unset": bson.M{"auditProjectionPending": ""}})
	if err != nil {
		return false, err
	}
	// MatchedCount is the ownership CAS. A second reconciler may rebuild the
	// same projection, but it must not acknowledge work it did not clear.
	return result.MatchedCount == 1, nil
}

func (mw *MongoWriter) advanceCwdProjectionGeneration(ctx context.Context, sourceID any) (cwdProjectionWork, error) {
	return mw.advanceCwdProjectionGenerationForEvent(ctx, sourceID)
}

func (mw *MongoWriter) advanceCwdProjectionGenerationForEvent(ctx context.Context, sourceID any) (cwdProjectionWork, error) {
	if sourceID == nil {
		return cwdProjectionWork{}, fmt.Errorf("CWD source identity is missing")
	}
	nextGeneration := bson.M{"$add": bson.A{bson.M{"$ifNull": bson.A{"$auditProjectionGeneration", int64(0)}}, int64(1)}}
	set := bson.M{
		"auditProjectionGeneration":        nextGeneration,
		"auditProjectionPendingGeneration": nextGeneration,
	}
	var state bson.M
	err := mw.db.Collection("cwd_session_state").FindOneAndUpdate(
		ctx,
		bson.M{"_id": sourceID},
		mongo.Pipeline{bson.D{{Key: "$set", Value: set}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&state)
	if err != nil {
		return cwdProjectionWork{}, err
	}
	return projectionWorkFromState(state, true), nil
}

func (mw *MongoWriter) closeCwdAuditProjection(ctx context.Context, sourceID any, sessionID string, generation int64, closedAt time.Time, retention time.Duration) error {
	if err := mw.backfillCwdAuditProjectionSession(ctx, sessionID, retention); err != nil {
		return err
	}
	collection := mw.db.Collection(cwdAuditProjectionCollection)
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": sessionID, "lifecycle.status": bson.M{"$ne": "closed"}},
		bson.M{
			"$set": bson.M{
				"sessionId":                 sessionID,
				"lifecycle.status":          "closed",
				"lifecycle.closedAt":        closedAt,
				"updatedAt":                 closedAt,
				"expires_at":                expiryAt(closedAt, retention),
				"auditProjectionVersion":    cwdAuditProjectionVersion,
				"auditProjectionGeneration": generation,
			},
			"$setOnInsert": bson.M{
				"schemaVersion":        cwdAuditProjectionVersion,
				"auditTransitionPaths": bson.A{},
				"auditVisitedPaths":    bson.A{},
				"auditPathsOverflow":   false,
				"auditEventCount":      0,
				"auditHistoryRevision": int64(0),
				"auditHomeOnly":        false,
			},
		},
	)
	if err != nil || result.MatchedCount > 0 {
		if err != nil {
			return err
		}
		return mw.markCwdAuditSourceReady(ctx, sourceID, generation)
	}
	// A close may arrive before the first CWD observation. Insert only when no
	// projection exists; an already-closed row is never rewritten.
	findErr := collection.FindOne(ctx, bson.M{"_id": sessionID}, options.FindOne().SetProjection(bson.M{"_id": 1})).Decode(&bson.M{})
	if findErr == nil {
		return mw.markCwdAuditSourceReady(ctx, sourceID, generation)
	}
	if findErr != mongo.ErrNoDocuments {
		return findErr
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": sessionID, "lifecycle.status": bson.M{"$ne": "closed"}}, bson.M{
		"$set": bson.M{
			"sessionId": sessionID, "lifecycle.status": "closed", "lifecycle.closedAt": closedAt,
			"updatedAt": closedAt, "expires_at": expiryAt(closedAt, retention), "auditProjectionVersion": cwdAuditProjectionVersion,
			"auditProjectionGeneration": generation,
		},
		"$setOnInsert": bson.M{"schemaVersion": cwdAuditProjectionVersion, "auditTransitionPaths": bson.A{}, "auditVisitedPaths": bson.A{}, "auditPathsOverflow": false, "auditEventCount": 0, "auditHistoryRevision": int64(0), "auditHomeOnly": false},
	}, options.Update().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return mw.markCwdAuditSourceReady(ctx, sourceID, generation)
	}
	if err != nil {
		return err
	}
	return mw.markCwdAuditSourceReady(ctx, sourceID, generation)
}

func auditProjectionSessionID(document bson.M) string {
	for _, field := range []string{"sessionId", "session_id", "_id"} {
		if value, ok := document[field].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sourceBSONExpiry(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, !typed.IsZero()
	case primitive.DateTime:
		return typed.Time(), true
	default:
		return time.Time{}, false
	}
}

// normalizeCwdSourceExpiry repairs the TTL authority without changing a valid
// closed retention boundary. The source identity, state order, and generation
// are all guarded so a stale reconciler cannot overwrite a newer source row.
func (mw *MongoWriter) normalizeCwdSourceExpiry(ctx context.Context, state bson.M, retention time.Duration) (bson.M, error) {
	lifecycle, _ := state["lifecycle"].(bson.M)
	if lifecycle["status"] != "closed" {
		return state, nil
	}
	canonicalID := auditProjectionSessionID(state)
	_, expiryOK := sourceBSONExpiry(state["expires_at"])
	if expiryOK && state["auditCanonicalSessionId"] == canonicalID {
		return state, nil
	}
	closedAt, ok := bsonTime(lifecycle["closedAt"])
	if !ok || closedAt.IsZero() {
		return state, fmt.Errorf("closed CWD source %v has no valid closedAt", state["_id"])
	}
	filter := bson.M{"_id": state["_id"], "lifecycle.status": "closed"}
	for _, field := range []string{"sessionId", "session_id"} {
		if value, exists := state[field]; exists {
			filter[field] = value
		}
	}
	for _, field := range []string{"auditProjectionGeneration", "stateSequence", "stateSourceEventId"} {
		if value, exists := state[field]; exists {
			filter[field] = value
		}
	}
	expiresAt := expiryAt(closedAt, retention)
	set := bson.M{"auditCanonicalSessionId": canonicalID}
	if !expiryOK {
		set["expires_at"] = expiresAt
	}
	result, err := mw.db.Collection("cwd_session_state").UpdateOne(ctx, filter, bson.M{"$set": set})
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 1 {
		state["auditCanonicalSessionId"] = canonicalID
		if !expiryOK {
			state["expires_at"] = expiresAt
		}
		return state, nil
	}
	var current bson.M
	if err := mw.db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": state["_id"]}).Decode(&current); err != nil {
		return nil, err
	}
	if _, ok := sourceBSONExpiry(current["expires_at"]); !ok || current["auditCanonicalSessionId"] != canonicalID {
		return nil, fmt.Errorf("CWD source expiry normalization lost its guarded race for %v", state["_id"])
	}
	return current, nil
}

func (mw *MongoWriter) backfillCwdAuditProjection(ctx context.Context, retention time.Duration) error {
	states := mw.db.Collection("cwd_session_state")
	marker := bson.M{}
	markerErr := mw.db.Collection("cwd_audit_projection_meta").FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{"projectionVersion": 1, "backfillCompletedAt": 1})).Decode(&marker)
	if markerErr != nil && markerErr != mongo.ErrNoDocuments {
		return markerErr
	}
	processStates := func(work bson.M) error {
		contract := validCwdAuditSourceFilter()
		contract["$and"] = bson.A{bson.M{"$or": bson.A{work}}}
		cursor, err := states.Find(ctx, contract, options.Find().SetBatchSize(256))
		if err != nil {
			return err
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var state bson.M
			if err := cursor.Decode(&state); err != nil {
				return err
			}
			if auditProjectionSessionID(state) == "" {
				continue
			}
			claimed, err := mw.claimCwdAuditProjectionState(ctx, state)
			if err != nil {
				return err
			}
			if claimed == nil {
				continue
			}
			if err := mw.backfillCwdAuditProjectionState(ctx, claimed, retention); err != nil {
				return err
			}
		}
		return cursor.Err()
	}

	// These are deliberately separate bounded/index-backed cutover branches:
	// new writers publish generation-owned pending work, while old rolling
	// writers can still create eligible v1/unversioned rows without that field.
	if err := processStates(bson.M{"$or": bson.A{
		bson.M{"auditProjectionPendingGeneration": bson.M{"$exists": true}},
	}}); err != nil {
		return err
	}
	if err := processStates(bson.M{"auditProjectionVersion": bson.M{"$ne": cwdAuditProjectionVersion}}); err != nil {
		return err
	}

	// A pending event is itself durable reconciliation work. It is intentionally
	// queried independently of source generations so an event committed after a
	// close writer has finished cannot disappear behind the newer generation.
	// Process the indexed cursor incrementally. Do not materialize an
	// unbounded pending-event slice in the reconciliation loop.
	eventCursor, err := mw.db.Collection("cwd_events").Find(ctx, bson.M{"auditProjectionPending": true}, options.Find().SetProjection(bson.M{"_id": 1, "eventId": 1, "sessionId": 1, "session_id": 1}).SetBatchSize(256))
	if err != nil {
		return err
	}
	for eventCursor.Next(ctx) {
		var event bson.M
		if err := eventCursor.Decode(&event); err != nil {
			eventCursor.Close(ctx)
			return err
		}
		eventID, _ := event["eventId"].(string)
		if eventID == "" {
			eventID = fmt.Sprint(event["_id"])
		}
		sessionID := auditProjectionSessionID(event)
		if eventID == "" || sessionID == "" {
			continue
		}
		converged, err := mw.backfillCwdAuditProjectionSessionResult(ctx, sessionID, retention)
		if err != nil {
			return err
		}
		if converged {
			if _, err := mw.clearCwdEventProjectionWork(ctx, eventID); err != nil {
				return err
			}
		}
	}
	if err := eventCursor.Err(); err != nil {
		eventCursor.Close(ctx)
		return err
	}
	if err := eventCursor.Close(ctx); err != nil {
		return err
	}

	// These existence checks are bounded and use the same branch predicates as
	// the reconciliation cursors. Do not publish a completion hint while either
	// protocol can still expose work.
	for _, pending := range []struct {
		collection *mongo.Collection
		filter     bson.M
		message    string
	}{
		{states, bson.M{"lifecycle.status": "closed", "$expr": validCwdAuditSourceExpression(), "auditProjectionPendingGeneration": bson.M{"$exists": true}}, "CWD audit projection generation work did not converge"},
		{states, bson.M{"lifecycle.status": "closed", "$expr": validCwdAuditSourceExpression(), "auditProjectionVersion": bson.M{"$ne": cwdAuditProjectionVersion}}, "CWD audit projection cutover work did not converge"},
	} {
		var pendingDoc bson.M
		if err := pending.collection.FindOne(ctx, pending.filter, options.FindOne().SetProjection(bson.M{"_id": 1})).Decode(&pendingDoc); err != mongo.ErrNoDocuments {
			if err != nil {
				return err
			}
			return fmt.Errorf("%s", pending.message)
		}
	}
	var pendingEvent bson.M
	if err := mw.db.Collection("cwd_events").FindOne(ctx, bson.M{"auditProjectionPending": true}, options.FindOne().SetProjection(bson.M{"_id": 1})).Decode(&pendingEvent); err != mongo.ErrNoDocuments {
		if err != nil {
			return err
		}
		return fmt.Errorf("CWD audit event work did not converge")
	}
	if err := mw.repairMissingCwdAuditProjections(ctx, retention); err != nil {
		return err
	}
	if _, err := mw.cleanupOrphanedCwdAuditProjections(ctx, time.Now().UTC(), retention); err != nil {
		return err
	}
	_, err = mw.db.Collection("cwd_audit_projection_meta").UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$set": bson.M{"projectionVersion": cwdAuditProjectionVersion, "backfillCompletedAt": time.Now().UTC()}}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	log.Printf("CWD audit projection backfill complete")
	return nil
}

// repairMissingCwdAuditProjections is the recovery half of the retention
// protocol. A projection is not independently TTL-managed, but a crash,
// operator action, or an old deployment can still leave a v2-ready source row
// without its read model. Each pass examines at most one indexed batch per
// canonical source field and stores a resumable cursor in the readiness meta
// document. Repeated/concurrent passes may claim the same row; the generation
// and history CAS operations make that duplicate work idempotent.
func (mw *MongoWriter) repairMissingCwdAuditProjections(ctx context.Context, retention time.Duration) error {
	marker := bson.M{}
	if err := mw.db.Collection("cwd_audit_projection_meta").FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{"missingProjectionSessionCursor": 1, "missingProjectionLegacyCursor": 1})).Decode(&marker); err != nil && err != mongo.ErrNoDocuments {
		return err
	}
	if err := mw.repairMissingCwdAuditProjectionField(ctx, retention, "sessionId", "missingProjectionSessionCursor", marker); err != nil {
		return err
	}
	return mw.repairMissingCwdAuditProjectionField(ctx, retention, "session_id", "missingProjectionLegacyCursor", marker)
}

type cwdRepairCursor struct {
	Value string
	ID    any
}

func missingCwdAuditProjectionKeysetQuery(field string, cursor *cwdRepairCursor) bson.M {
	match := bson.M{
		"lifecycle.status": "closed",
		field:              bson.M{"$type": "string"},
	}
	if cursor != nil {
		match["$or"] = bson.A{
			bson.M{field: bson.M{"$gt": cursor.Value}},
			bson.M{field: cursor.Value, "_id": bson.M{"$gt": cursor.ID}},
		}
	}
	return match
}

func decodeCwdRepairCursor(value any) *cwdRepairCursor {
	document, ok := value.(bson.M)
	if !ok {
		return nil
	}
	rawValue, valueOK := document["value"].(string)
	rawID, idOK := document["id"]
	if !valueOK || !idOK || rawID == nil {
		return nil
	}
	return &cwdRepairCursor{Value: rawValue, ID: rawID}
}

func cwdRepairCursorDocument(cursor *cwdRepairCursor) bson.M {
	return bson.M{"value": cursor.Value, "id": cursor.ID}
}

func cwdRepairCursorCASFilter(cursorKey string, cursor *cwdRepairCursor) bson.M {
	filter := bson.M{"_id": cwdAuditProjectionMetaID}
	if cursor == nil {
		filter[cursorKey] = bson.M{"$exists": false}
	} else {
		filter[cursorKey+".value"] = cursor.Value
		filter[cursorKey+".id"] = cursor.ID
	}
	return filter
}

func (mw *MongoWriter) repairMissingCwdAuditProjectionField(ctx context.Context, retention time.Duration, field, cursorKey string, marker bson.M) error {
	start := decodeCwdRepairCursor(marker[cursorKey])
	states := mw.db.Collection("cwd_session_state")
	findOptions := options.Find().SetProjection(bson.M{"_id": 1, "sessionId": 1, "session_id": 1, "sourceIp": 1, "cwdState": 1, "lifecycle": 1, "stateSequence": 1, "stateSourceEventId": 1, "auditProjectionGeneration": 1, "auditProjectionReadyGeneration": 1, "auditProjectionVersion": 1, "expires_at": 1}).SetSort(bson.D{{Key: field, Value: 1}, {Key: "_id", Value: 1}}).SetLimit(cwdAuditProjectionRepairBatchSize)
	cursorResult, err := states.Find(ctx, missingCwdAuditProjectionKeysetQuery(field, start), findOptions)
	if err != nil {
		return err
	}
	defer cursorResult.Close(ctx)
	var batch []bson.M
	if err := cursorResult.All(ctx, &batch); err != nil {
		return err
	}
	if err := cursorResult.Close(ctx); err != nil {
		return err
	}
	last := start
	for _, state := range batch {
		rawValue, rawOK := state[field].(string)
		if rawOK {
			last = &cwdRepairCursor{Value: rawValue, ID: state["_id"]}
		}
		if !rawOK {
			continue
		}
		if !cwdAuditSourceReadyForRepair(state) {
			continue
		}
		sessionID := strings.TrimSpace(rawValue)
		if sessionID == "" {
			continue
		}
		if !validCwdAuditRepairState(state, sessionID) {
			continue
		}
		state, err = mw.normalizeCwdSourceExpiry(ctx, state, retention)
		if err != nil {
			return err
		}
		var projection bson.M
		if err := mw.db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": sessionID}, options.FindOne().SetProjection(bson.M{"_id": 1, "expires_at": 1})).Decode(&projection); err == nil {
			projectionExpiry, expiryOK := sourceBSONExpiry(projection["expires_at"])
			sourceExpiry, sourceExpiryOK := sourceBSONExpiry(state["expires_at"])
			if expiryOK && sourceExpiryOK && projectionExpiry.Equal(sourceExpiry) {
				continue
			}
			if err := mw.backfillCwdAuditProjectionState(ctx, state, retention); err != nil {
				return err
			}
			continue
		} else if err != mongo.ErrNoDocuments {
			return err
		}
		claimed, err := mw.claimCwdAuditProjectionState(ctx, state)
		if err != nil {
			return err
		}
		if claimed != nil {
			if err := mw.backfillCwdAuditProjectionState(ctx, claimed, retention); err != nil {
				return err
			}
		}
	}
	meta := mw.db.Collection("cwd_audit_projection_meta")
	if _, err := meta.UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$setOnInsert": bson.M{"_id": cwdAuditProjectionMetaID}}, options.Update().SetUpsert(true)); err != nil {
		return err
	}
	if len(batch) == 0 {
		if start == nil {
			return nil
		}
		result, err := meta.UpdateOne(ctx, cwdRepairCursorCASFilter(cursorKey, start), bson.M{"$unset": bson.M{cursorKey: ""}})
		if err != nil || result.MatchedCount == 0 {
			return err
		}
		// A newly eligible row may sort before the saved cursor. Wrap in the
		// same reconciliation call after the CAS-owned cursor reset so it is
		// not delayed until a later close event or periodic pass.
		wrappedMarker := bson.M{}
		if err := meta.FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{cursorKey: 1})).Decode(&wrappedMarker); err != nil && err != mongo.ErrNoDocuments {
			return err
		}
		return mw.repairMissingCwdAuditProjectionField(ctx, retention, field, cursorKey, wrappedMarker)
	}
	if last == nil {
		return nil
	}
	result, err := meta.UpdateOne(ctx, cwdRepairCursorCASFilter(cursorKey, start), bson.M{"$set": bson.M{cursorKey: cwdRepairCursorDocument(last)}})
	if err == nil && result.MatchedCount != 1 {
		// Another reconciler owns a newer cursor. Its CAS is authoritative; do
		// not overwrite it or treat a lost duplicate claim as progress.
		return nil
	}
	return err
}

func cwdAuditSourceReadyForRepair(state bson.M) bool {
	if state["auditProjectionVersion"] != cwdAuditProjectionVersion {
		return false
	}
	if _, ready := state["auditProjectionReadyGeneration"]; !ready {
		return false
	}
	_, pending := state["auditProjectionPendingGeneration"]
	return !pending
}

func validCwdAuditRepairState(state bson.M, sessionID string) bool {
	if sessionID == "" {
		return false
	}
	lifecycle, lifecycleOK := state["lifecycle"].(bson.M)
	if !lifecycleOK || lifecycle["status"] != "closed" {
		return false
	}
	if _, closedOK := bsonTime(lifecycle["closedAt"]); !closedOK {
		return false
	}
	cwdState, cwdStateOK := state["cwdState"].(bson.M)
	path, pathOK := cwdState["path"].(string)
	return cwdStateOK && pathOK && strings.HasPrefix(strings.TrimSpace(path), "/")
}

// cleanupOrphanedCwdAuditProjections is intentionally source-authoritative:
// an expired projection is deleted only after an indexed source lookup proves
// that cwd_session_state is absent. A source row delayed by MongoDB's TTL
// monitor therefore keeps its projection, and orphan cleanup remains bounded
// by cwdAuditProjectionRepairBatchSize per reconciliation pass.
type cwdCleanupCursor struct {
	ExpiresAt time.Time
	ID        any
}

func cwdAuditProjectionCleanupKeysetQuery(now time.Time, cursor *cwdCleanupCursor) bson.M {
	match := bson.M{"expires_at": bson.M{"$type": "date", "$lte": now}}
	if cursor != nil {
		match["$or"] = bson.A{
			bson.M{"expires_at": bson.M{"$type": "date", "$gt": cursor.ExpiresAt, "$lte": now}},
			bson.M{"expires_at": cursor.ExpiresAt, "_id": bson.M{"$gt": cursor.ID}},
		}
	}
	return match
}

func decodeCwdCleanupCursor(value any) *cwdCleanupCursor {
	document, ok := value.(bson.M)
	if !ok {
		return nil
	}
	expiresAt, expiresOK := bsonTime(document["expiresAt"])
	id, idOK := document["id"]
	if !expiresOK || id == nil || !idOK {
		return nil
	}
	return &cwdCleanupCursor{ExpiresAt: expiresAt, ID: id}
}

func cwdCleanupCursorDocument(cursor *cwdCleanupCursor) bson.M {
	return bson.M{"expiresAt": cursor.ExpiresAt, "id": cursor.ID}
}

func cwdCleanupCursorCASFilter(cursorKey string, cursor *cwdCleanupCursor) bson.M {
	filter := bson.M{"_id": cwdAuditProjectionMetaID}
	if cursor == nil {
		filter[cursorKey] = bson.M{"$exists": false}
	} else {
		filter[cursorKey+".expiresAt"] = cursor.ExpiresAt
		filter[cursorKey+".id"] = cursor.ID
	}
	return filter
}

func (mw *MongoWriter) cleanupOrphanedCwdAuditProjections(ctx context.Context, now time.Time, retention time.Duration) (int64, error) {
	malformedDeleted, err := mw.cleanupMalformedCwdAuditProjections(ctx, retention)
	if err != nil {
		return 0, err
	}
	projections := mw.db.Collection(cwdAuditProjectionCollection)
	meta := mw.db.Collection("cwd_audit_projection_meta")
	marker := bson.M{}
	if err := meta.FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{"cleanupProjectionCursor": 1})).Decode(&marker); err != nil && err != mongo.ErrNoDocuments {
		return 0, err
	}
	start := decodeCwdCleanupCursor(marker["cleanupProjectionCursor"])
	original := start
	findOptions := options.Find().SetProjection(bson.M{"_id": 1, "sessionId": 1, "session_id": 1, "expires_at": 1}).SetSort(bson.D{{Key: "expires_at", Value: 1}, {Key: "_id", Value: 1}}).SetLimit(cwdAuditProjectionRepairBatchSize)
	rows, err := projections.Find(ctx, cwdAuditProjectionCleanupKeysetQuery(now, start), findOptions)
	if err != nil {
		return 0, err
	}
	defer rows.Close(ctx)
	var deleted int64 = malformedDeleted
	batchCount := 0
	for rows.Next(ctx) {
		batchCount++
		var projection bson.M
		if err := rows.Decode(&projection); err != nil {
			return deleted, err
		}
		expiresAt, expiresOK := bsonTime(projection["expires_at"])
		if expiresOK {
			start = &cwdCleanupCursor{ExpiresAt: expiresAt, ID: projection["_id"]}
		}
		sessionID := auditProjectionSessionID(projection)
		if sessionID == "" {
			continue
		}
		if _, err := mw.findCwdStateByIndexedCanonicalID(ctx, sessionID); err == nil {
			continue
		} else if err != mongo.ErrNoDocuments {
			return deleted, err
		}
		if mw.auditBeforeCwdProjectionDelete != nil {
			mw.auditBeforeCwdProjectionDelete(sessionID)
		}
		if _, err := mw.findCwdStateByIndexedCanonicalID(ctx, sessionID); err == nil {
			continue
		} else if err != mongo.ErrNoDocuments {
			return deleted, err
		}
		result, err := projections.DeleteOne(ctx, bson.M{"_id": projection["_id"], "expires_at": expiresAt})
		if err != nil {
			return deleted, err
		}
		deleted += result.DeletedCount
	}
	if err := rows.Err(); err != nil {
		return deleted, err
	}
	if err := rows.Close(ctx); err != nil {
		return deleted, err
	}
	if _, err := meta.UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$setOnInsert": bson.M{"_id": cwdAuditProjectionMetaID}}, options.Update().SetUpsert(true)); err != nil {
		return deleted, err
	}
	if batchCount == 0 {
		if original == nil {
			return deleted, nil
		}
		result, err := meta.UpdateOne(ctx, cwdCleanupCursorCASFilter("cleanupProjectionCursor", original), bson.M{"$unset": bson.M{"cleanupProjectionCursor": ""}})
		if err != nil || result.MatchedCount != 1 {
			// A concurrent cleanup pass owns a newer cursor or has already
			// wrapped it. Its CAS result is authoritative; retrying the bounded
			// work on the next pass is safe and cannot regress that cursor.
			return deleted, err
		}
		return deleted, nil
	}
	if start == nil {
		return deleted, nil
	}
	result, err := meta.UpdateOne(ctx, cwdCleanupCursorCASFilter("cleanupProjectionCursor", original), bson.M{"$set": bson.M{"cleanupProjectionCursor": cwdCleanupCursorDocument(start)}})
	if err != nil {
		return deleted, err
	}
	if result.MatchedCount != 1 {
		return deleted, nil
	}
	return deleted, nil
}

type cwdMalformedProjectionCursor struct {
	ID any
}

func decodeCwdMalformedProjectionCursor(value any) *cwdMalformedProjectionCursor {
	document, ok := value.(bson.M)
	if !ok || document["id"] == nil {
		return nil
	}
	return &cwdMalformedProjectionCursor{ID: document["id"]}
}

func cwdMalformedProjectionCursorDocument(cursor *cwdMalformedProjectionCursor) bson.M {
	return bson.M{"id": cursor.ID}
}

func cwdMalformedProjectionCursorCASFilter(cursor *cwdMalformedProjectionCursor) bson.M {
	filter := bson.M{"_id": cwdAuditProjectionMetaID}
	if cursor == nil {
		filter["malformedProjectionCursor"] = bson.M{"$exists": false}
	} else {
		filter["malformedProjectionCursor.id"] = cursor.ID
	}
	return filter
}

func malformedProjectionExpiryDeleteFilter(projection bson.M) bson.M {
	filter := bson.M{"_id": projection["_id"]}
	if value, exists := projection["expires_at"]; exists {
		filter["expires_at"] = value
	} else {
		filter["expires_at"] = bson.M{"$exists": false}
	}
	return filter
}

func (mw *MongoWriter) cleanupMalformedCwdAuditProjections(ctx context.Context, retention time.Duration) (int64, error) {
	projections := mw.db.Collection(cwdAuditProjectionCollection)
	meta := mw.db.Collection("cwd_audit_projection_meta")
	marker := bson.M{}
	if err := meta.FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{"malformedProjectionCursor": 1})).Decode(&marker); err != nil && err != mongo.ErrNoDocuments {
		return 0, err
	}
	original := decodeCwdMalformedProjectionCursor(marker["malformedProjectionCursor"])
	start := original
	filter := bson.M{}
	if start != nil {
		filter["_id"] = bson.M{"$gt": start.ID}
	}
	rows, err := projections.Find(ctx, filter, options.Find().SetProjection(bson.M{"_id": 1, "sessionId": 1, "session_id": 1, "expires_at": 1}).SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(cwdAuditProjectionRepairBatchSize))
	if err != nil {
		return 0, err
	}
	defer rows.Close(ctx)
	var deleted int64
	batchCount := 0
	for rows.Next(ctx) {
		batchCount++
		var projection bson.M
		if err := rows.Decode(&projection); err != nil {
			return deleted, err
		}
		start = &cwdMalformedProjectionCursor{ID: projection["_id"]}
		if _, valid := sourceBSONExpiry(projection["expires_at"]); valid {
			continue
		}
		sessionID := auditProjectionSessionID(projection)
		if sessionID != "" {
			state, lookupErr := mw.findCwdStateByIndexedCanonicalID(ctx, sessionID)
			if lookupErr == nil {
				if err := mw.backfillCwdAuditProjectionState(ctx, state, retention); err != nil {
					return deleted, err
				}
				continue
			}
			if lookupErr != mongo.ErrNoDocuments {
				return deleted, lookupErr
			}
		}
		if mw.auditBeforeCwdProjectionDelete != nil {
			mw.auditBeforeCwdProjectionDelete(sessionID)
		}
		if sessionID != "" {
			if _, lookupErr := mw.findCwdStateByIndexedCanonicalID(ctx, sessionID); lookupErr == nil {
				continue
			} else if lookupErr != mongo.ErrNoDocuments {
				return deleted, lookupErr
			}
		}
		result, err := projections.DeleteOne(ctx, malformedProjectionExpiryDeleteFilter(projection))
		if err != nil {
			return deleted, err
		}
		deleted += result.DeletedCount
	}
	if err := rows.Err(); err != nil {
		return deleted, err
	}
	if err := rows.Close(ctx); err != nil {
		return deleted, err
	}
	if _, err := meta.UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$setOnInsert": bson.M{"_id": cwdAuditProjectionMetaID}}, options.Update().SetUpsert(true)); err != nil {
		return deleted, err
	}
	if batchCount == 0 {
		if original == nil {
			return deleted, nil
		}
		result, err := meta.UpdateOne(ctx, cwdMalformedProjectionCursorCASFilter(original), bson.M{"$unset": bson.M{"malformedProjectionCursor": ""}})
		if err != nil || result.MatchedCount != 1 {
			return deleted, err
		}
		return deleted, nil
	}
	if start == nil {
		return deleted, nil
	}
	result, err := meta.UpdateOne(ctx, cwdMalformedProjectionCursorCASFilter(original), bson.M{"$set": bson.M{"malformedProjectionCursor": cwdMalformedProjectionCursorDocument(start)}})
	if err != nil || result.MatchedCount != 1 {
		return deleted, err
	}
	return deleted, nil
}

func (mw *MongoWriter) claimCwdAuditProjectionState(ctx context.Context, state bson.M) (bson.M, error) {
	sourceID := state["_id"]
	if sourceID == nil {
		return nil, nil
	}
	generation := bson.M{"$ifNull": bson.A{"$auditProjectionGeneration", int64(1)}}
	var claimed bson.M
	err := mw.db.Collection("cwd_session_state").FindOneAndUpdate(
		ctx,
		bson.M{"_id": sourceID},
		mongo.Pipeline{bson.D{{Key: "$set", Value: bson.M{
			"auditProjectionGeneration":        generation,
			"auditProjectionPendingGeneration": generation,
			"auditCanonicalSessionId":          auditProjectionSessionID(state),
		}}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&claimed)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return claimed, err
}

func indexedCwdStateCanonicalQuery(sessionID string) bson.M {
	return bson.M{"auditCanonicalSessionId": sessionID}
}

func (mw *MongoWriter) findCwdStateByIndexedCanonicalID(ctx context.Context, sessionID string) (bson.M, error) {
	queries := []bson.M{
		indexedCwdStateCanonicalQuery(sessionID),
		{"_id": sessionID},
		{"sessionId": sessionID},
		{"session_id": sessionID},
	}
	for _, query := range queries {
		var state bson.M
		err := mw.db.Collection("cwd_session_state").FindOne(ctx, query).Decode(&state)
		if err == nil {
			return state, nil
		}
		if err != mongo.ErrNoDocuments {
			return nil, err
		}
	}
	return nil, mongo.ErrNoDocuments
}

func (mw *MongoWriter) backfillCwdAuditProjectionSession(ctx context.Context, sessionID string, retention time.Duration) error {
	_, err := mw.backfillCwdAuditProjectionSessionResult(ctx, sessionID, retention)
	return err
}

func (mw *MongoWriter) backfillCwdAuditProjectionSessionResult(ctx context.Context, sessionID string, retention time.Duration) (bool, error) {
	state, err := mw.findCwdStateByCanonicalID(ctx, sessionID)
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	claimed, err := mw.claimCwdAuditProjectionState(ctx, state)
	if err != nil || claimed == nil {
		return false, err
	}
	if err := mw.backfillCwdAuditProjectionState(ctx, claimed, retention); err != nil {
		return false, err
	}
	var current bson.M
	if err := mw.db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": claimed["_id"]}, options.FindOne().SetProjection(bson.M{"auditProjectionGeneration": 1, "auditProjectionReadyGeneration": 1, "auditProjectionPendingGeneration": 1})).Decode(&current); err != nil {
		return false, err
	}
	generation := bsonInt64(claimed["auditProjectionGeneration"])
	return bsonInt64(current["auditProjectionReadyGeneration"]) == generation && current["auditProjectionPendingGeneration"] == nil, nil
}

func (mw *MongoWriter) findCwdStateByCanonicalID(ctx context.Context, sessionID string) (bson.M, error) {
	var state bson.M
	states := mw.db.Collection("cwd_session_state")
	err := states.FindOne(ctx, bson.M{"$or": bson.A{
		bson.M{"_id": sessionID},
		bson.M{"sessionId": sessionID},
		bson.M{"session_id": sessionID},
	}}).Decode(&state)
	if err != mongo.ErrNoDocuments {
		return state, err
	}
	// Migration-only compatibility path for padded identifiers. Normal writer
	// rows use the indexed exact branches above and never reach this scan.
	return state, states.FindOne(ctx, bson.M{
		"$expr": bson.M{"$or": bson.A{
			bson.M{"$eq": bson.A{trimmedAuditStringExpression("$sessionId"), sessionID}},
			bson.M{"$eq": bson.A{trimmedAuditStringExpression("$session_id"), sessionID}},
		}},
	}).Decode(&state)
}

func (mw *MongoWriter) backfillCwdAuditProjectionState(ctx context.Context, state bson.M, retention time.Duration) error {
	normalized, err := mw.normalizeCwdSourceExpiry(ctx, state, retention)
	if err != nil {
		return err
	}
	state = normalized
	sessionID := auditProjectionSessionID(state)
	if sessionID == "" {
		return nil
	}
	transitionPaths := bson.A{}
	eventCount := 0
	seenEventIDs := map[string]struct{}{}
	statePath := ""
	canonicalCwdState := bson.M{}
	if cwdState, ok := state["cwdState"].(bson.M); ok {
		for key, value := range cwdState {
			canonicalCwdState[key] = value
		}
		statePath, _ = cwdState["path"].(string)
		statePath = strings.TrimSpace(statePath)
		canonicalCwdState["path"] = statePath
	}
	// Capture the projection's history generation before reading cwd_events.
	// A late event increments this generation in the event update, making the
	// delayed snapshot update miss its CAS instead of restoring an old count.
	var currentProjection bson.M
	historyRevision := int64(0)
	hasHistoryRevision := false
	projection := mw.db.Collection(cwdAuditProjectionCollection)
	projectionErr := projection.FindOne(ctx, bson.M{"_id": sessionID}, options.FindOne().SetProjection(bson.M{"auditHistoryRevision": 1})).Decode(&currentProjection)
	if projectionErr != nil && projectionErr != mongo.ErrNoDocuments {
		return projectionErr
	}
	if projectionErr == nil {
		historyRevision = bsonInt64(currentProjection["auditHistoryRevision"])
		_, hasHistoryRevision = currentProjection["auditHistoryRevision"]
	}
	consumeHistory := func(query bson.M) error {
		historyCursor, err := mw.db.Collection("cwd_events").Find(ctx, query, options.Find().SetProjection(bson.M{"_id": 1, "eventId": 1, "fromPath": 1, "toPath": 1, "action": 1}))
		if err != nil {
			return err
		}
		for historyCursor.Next(ctx) {
			var event bson.M
			if err := historyCursor.Decode(&event); err != nil {
				historyCursor.Close(ctx)
				return err
			}
			id, _ := event["eventId"].(string)
			if id == "" {
				id = fmt.Sprint(event["_id"])
			}
			if _, exists := seenEventIDs[id]; exists {
				continue
			}
			seenEventIDs[id] = struct{}{}
			eventCount++
			if from, ok := event["fromPath"].(string); ok {
				transitionPaths = append(transitionPaths, from)
			}
			if event["action"] != "failed_change" {
				if to, ok := event["toPath"].(string); ok {
					transitionPaths = append(transitionPaths, to)
				}
			}
		}
		if err := historyCursor.Err(); err != nil {
			historyCursor.Close(ctx)
			return fmt.Errorf("CWD audit history cursor: %w", err)
		}
		return historyCursor.Close(ctx)
	}
	if err := consumeHistory(bson.M{"$or": bson.A{bson.M{"sessionId": sessionID}, bson.M{"session_id": sessionID}}, "action": bson.M{"$in": bson.A{"entered", "changed", "failed_change"}}}); err != nil {
		return err
	}
	if historyNeedsCompatibility(state) {
		if err := consumeHistory(bson.M{
			"$and": bson.A{
				bson.M{"action": bson.M{"$in": bson.A{"entered", "changed", "failed_change"}}},
				bson.M{"$expr": bson.M{"$or": bson.A{
					bson.M{"$eq": bson.A{trimmedAuditStringExpression("$sessionId"), sessionID}},
					bson.M{"$eq": bson.A{trimmedAuditStringExpression("$session_id"), sessionID}},
				}}},
			},
		}); err != nil {
			return err
		}
	}
	if mw.auditBackfillAfterHistoryRead != nil {
		mw.auditBackfillAfterHistoryRead()
	}
	transitionPaths = uniqueStrings(transitionPaths)
	lifecycle, _ := state["lifecycle"].(bson.M)
	canonicalLifecycle := bson.M{}
	for key, value := range lifecycle {
		canonicalLifecycle[key] = value
	}
	if closedAt, ok := bsonTime(canonicalLifecycle["closedAt"]); ok {
		canonicalLifecycle["closedAt"] = closedAt
	}
	lifecycle = canonicalLifecycle
	sequence, sourceEventID := cwdAuditSourceOrder(state)
	filter := bson.M{"_id": sessionID, "$or": bson.A{
		bson.M{"stateSequence": bson.M{"$lt": sequence}},
		bson.M{"stateSequence": sequence, "stateSourceEventId": bson.M{"$lte": sourceEventID}},
		bson.M{"stateSequence": sequence, "stateSourceEventId": bson.M{"$exists": false}},
		bson.M{"stateSequence": bson.M{"$exists": false}},
	}}
	if status, _ := lifecycle["status"].(string); status != "closed" {
		filter["lifecycle.status"] = bson.M{"$ne": "closed"}
	}
	if _, err := projection.UpdateOne(ctx, bson.M{"_id": sessionID}, bson.M{"$setOnInsert": bson.M{"_id": sessionID, "auditTransitionPaths": bson.A{}, "auditEventCount": 0, "auditHistoryRevision": int64(0)}}, options.Update().SetUpsert(true)); err != nil {
		return err
	}
	if projectionErr == mongo.ErrNoDocuments {
		historyRevision = 0
	}
	revisionFilter := bson.M{"auditHistoryRevision": historyRevision}
	if !hasHistoryRevision {
		revisionFilter = bson.M{"$or": bson.A{
			bson.M{"auditHistoryRevision": historyRevision},
			bson.M{"auditHistoryRevision": bson.M{"$exists": false}},
		}}
	}
	filter["$and"] = bson.A{revisionFilter, bson.M{"$or": filter["$or"]}}
	delete(filter, "$or")
	transitionExpr := bson.M{"$setUnion": bson.A{bson.M{"$ifNull": bson.A{"$auditTransitionPaths", bson.A{}}}, transitionPaths}}
	boundedTransitionExpr := bson.M{"$slice": bson.A{transitionExpr, cwdAuditProjectionMaxPaths}}
	currentPath := bson.M{"$map": bson.M{"input": bson.A{1}, "as": "ignored", "in": statePath}}
	visitedExpr := bson.M{"$filter": bson.M{"input": bson.M{"$setUnion": bson.A{boundedTransitionExpr, currentPath}}, "as": "path", "cond": bson.M{"$and": bson.A{bson.M{"$ne": bson.A{"$$path", nil}}, bson.M{"$ne": bson.A{"$$path", ""}}, bson.M{"$regexMatch": bson.M{"input": "$$path", "regex": "^/"}}}}}}
	generation := bsonInt64(state["auditProjectionGeneration"])
	set := bson.M{"schemaVersion": cwdAuditProjectionVersion, "sessionId": sessionID, "sourceIp": state["sourceIp"], "stateSequence": sequence, "stateSourceEventId": sourceEventID, "cwdState": canonicalCwdState, "lifecycle": lifecycle, "auditTransitionPaths": boundedTransitionExpr, "auditPathsOverflow": bson.M{"$gt": bson.A{bson.M{"$size": transitionExpr}, cwdAuditProjectionMaxPaths}}, "auditVisitedPaths": visitedExpr, "auditHomeOnly": auditProjectionHomeOnlyExpression(visitedExpr), "auditEventCount": eventCount, "auditHistoryRevision": int64(eventCount), "auditProjectionVersion": cwdAuditProjectionVersion, "auditProjectionGeneration": generation, "updatedAt": time.Now().UTC(), "expires_at": stateExpiry(state, retention)}
	result, err := projection.UpdateOne(ctx, filter, mongo.Pipeline{{{Key: "$set", Value: set}}, {{Key: "$unset", Value: bson.A{"auditEventIds", "visitedPaths", "eventCount", "homeOnly"}}}})
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		// A newer current-state or history generation won the race. Its writer
		// owns the durable projection; leave the source pending generation for
		// the next incremental pass.
		return nil
	}
	return mw.markCwdAuditSourceReady(ctx, state["_id"], generation)
}

func historyNeedsCompatibility(state bson.M) bool {
	for _, field := range []string{"sessionId", "session_id"} {
		if value, ok := state[field].(string); ok && strings.TrimSpace(value) != value {
			return true
		}
	}
	return false
}

func validCwdAuditSourceState(state bson.M) bool {
	if auditProjectionSessionID(state) == "" {
		return false
	}
	lifecycle, ok := state["lifecycle"].(bson.M)
	if !ok || lifecycle["status"] != "closed" {
		return false
	}
	cwdState, ok := state["cwdState"].(bson.M)
	path, pathOK := cwdState["path"].(string)
	_, closedOK := bsonTime(lifecycle["closedAt"])
	return ok && pathOK && strings.HasPrefix(strings.TrimSpace(path), "/") && closedOK
}

func trimmedAuditStringExpression(field string) bson.M {
	return bson.M{"$cond": bson.A{
		bson.M{"$eq": bson.A{bson.M{"$type": field}, "string"}},
		bson.M{"$trim": bson.M{"input": field}},
		nil,
	}}
}

func canonicalAuditSessionExpression() bson.M {
	return bson.M{"$let": bson.M{
		"vars": bson.M{
			"sessionId":       trimmedAuditStringExpression("$sessionId"),
			"legacySessionId": trimmedAuditStringExpression("$session_id"),
		},
		"in": bson.M{"$cond": bson.A{
			bson.M{"$and": bson.A{bson.M{"$ne": bson.A{"$$sessionId", nil}}, bson.M{"$ne": bson.A{"$$sessionId", ""}}}}, "$$sessionId",
			bson.M{"$cond": bson.A{bson.M{"$and": bson.A{bson.M{"$ne": bson.A{"$$legacySessionId", nil}}, bson.M{"$ne": bson.A{"$$legacySessionId", ""}}}}, "$$legacySessionId", nil}},
		}},
	}}
}

func validCwdAuditSourceExpression() bson.M {
	closedAt := bson.M{"$convert": bson.M{"input": "$lifecycle.closedAt", "to": "date", "onError": nil, "onNull": nil}}
	path := bson.M{"$ifNull": bson.A{trimmedAuditStringExpression("$cwdState.path"), ""}}
	return bson.M{"$and": bson.A{
		bson.M{"$ne": bson.A{canonicalAuditSessionExpression(), nil}},
		bson.M{"$ne": bson.A{closedAt, nil}},
		bson.M{"$regexMatch": bson.M{"input": path, "regex": "^/"}},
	}}
}

func validCwdAuditSourceFilter() bson.M {
	return bson.M{"lifecycle.status": "closed", "$expr": validCwdAuditSourceExpression()}
}

func cwdAuditSourceOrder(state bson.M) (int64, string) {
	sequence := int64(0)
	switch value := state["stateSequence"].(type) {
	case int64:
		sequence = value
	case int32:
		sequence = int64(value)
	case int:
		sequence = int64(value)
	case float64:
		sequence = int64(value)
	}
	sourceEventID, _ := state["stateSourceEventId"].(string)
	if cwdState, ok := state["cwdState"].(bson.M); ok {
		if sourceEventID == "" {
			sourceEventID, _ = cwdState["sourceEventId"].(string)
		}
		if sequence == 0 {
			if observedAt, ok := bsonTime(cwdState["observedAt"]); ok {
				sequence = observedAt.UnixNano()
			}
		}
	}
	if sequence == 0 {
		if lifecycle, ok := state["lifecycle"].(bson.M); ok {
			if closedAt, ok := bsonTime(lifecycle["closedAt"]); ok {
				sequence = closedAt.UnixNano()
			}
		}
	}
	return sequence, sourceEventID
}

func stateExpiry(state bson.M, retention time.Duration) time.Time {
	if expires, ok := bsonTime(state["expires_at"]); ok && !expires.IsZero() {
		return expires
	}
	if lifecycle, ok := state["lifecycle"].(bson.M); ok {
		if closed, ok := bsonTime(lifecycle["closedAt"]); ok && !closed.IsZero() {
			return expiryAt(closed, retention)
		}
		if started, ok := bsonTime(lifecycle["startedAt"]); ok && !started.IsZero() {
			return expiryAt(started, retention)
		}
	}
	return time.Now().UTC().Add(retention)
}

func bsonTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case primitive.DateTime:
		return typed.Time(), true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(typed))
		if err == nil && !parsed.IsZero() {
			return parsed, true
		}
	default:
		return time.Time{}, false
	}
	return time.Time{}, false
}

func bsonInt64(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int32:
		return int64(typed)
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func uniqueStrings(values bson.A) bson.A {
	seen := make(map[string]struct{}, len(values))
	result := bson.A{}
	for _, raw := range values {
		value, ok := raw.(string)
		if !ok || value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func auditHomeOnly(paths bson.A) bool {
	hasHome := false
	hasOutside := false
	for _, raw := range paths {
		path, ok := raw.(string)
		if !ok || path == "/" {
			continue
		}
		if path == "/home" || strings.HasPrefix(path, "/home/") {
			hasHome = true
		} else {
			hasOutside = true
		}
	}
	return hasHome && !hasOutside
}
