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
	cwdAuditProjectionCollection = "cwd_audit_projection"
	cwdAuditProjectionVersion    = "cwd_audit_projection.v2"
	cwdAuditProjectionMetaID     = "audit-directory"
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
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
}

func cwdStateIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "updatedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "session_id", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditProjectionVersion", Value: 1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditProjectionPendingGeneration", Value: 1}}, Options: options.Index().SetPartialFilterExpression(bson.M{"auditProjectionPendingGeneration": bson.M{"$exists": true}})},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "auditProjectionPendingEventCount", Value: 1}}, Options: options.Index().SetPartialFilterExpression(bson.M{"auditProjectionPendingEventCount": bson.M{"$gt": 0}})},
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
			if err := mw.clearCwdEventProjectionWork(ctx, sourceID, eventID); err != nil {
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

func (mw *MongoWriter) clearCwdEventProjectionWork(ctx context.Context, sourceID any, eventID string) error {
	if _, err := mw.db.Collection("cwd_events").UpdateOne(ctx, bson.M{"_id": eventID, "auditProjectionPending": true}, bson.M{"$unset": bson.M{"auditProjectionPending": ""}}); err != nil {
		return err
	}
	_, err := mw.db.Collection("cwd_session_state").UpdateOne(ctx, bson.M{
		"_id":                              sourceID,
		"auditProjectionPendingEventCount": bson.M{"$gt": 0},
	}, bson.M{"$inc": bson.M{"auditProjectionPendingEventCount": -1}})
	return err
}

func (mw *MongoWriter) advanceCwdProjectionGeneration(ctx context.Context, sourceID any) (cwdProjectionWork, error) {
	return mw.advanceCwdProjectionGenerationForEvent(ctx, sourceID, false)
}

func (mw *MongoWriter) advanceCwdProjectionGenerationForEvent(ctx context.Context, sourceID any, eventWork bool) (cwdProjectionWork, error) {
	if sourceID == nil {
		return cwdProjectionWork{}, fmt.Errorf("CWD source identity is missing")
	}
	nextGeneration := bson.M{"$add": bson.A{bson.M{"$ifNull": bson.A{"$auditProjectionGeneration", int64(0)}}, int64(1)}}
	set := bson.M{
		"auditProjectionGeneration":        nextGeneration,
		"auditProjectionPendingGeneration": nextGeneration,
	}
	if eventWork {
		set["auditProjectionPendingEventCount"] = bson.M{"$add": bson.A{bson.M{"$ifNull": bson.A{"$auditProjectionPendingEventCount", int64(0)}}, int64(1)}}
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

func (mw *MongoWriter) backfillCwdAuditProjection(ctx context.Context, retention time.Duration) error {
	states := mw.db.Collection("cwd_session_state")
	marker := bson.M{}
	markerErr := mw.db.Collection("cwd_audit_projection_meta").FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, options.FindOne().SetProjection(bson.M{"projectionVersion": 1, "backfillCompletedAt": 1})).Decode(&marker)
	if markerErr != nil && markerErr != mongo.ErrNoDocuments {
		return markerErr
	}
	var eventWorkProbe bson.M
	eventWorkProbeErr := states.FindOne(ctx, bson.M{
		"lifecycle.status": "closed",
		"$expr":            validCwdAuditSourceExpression(),
		"$or": bson.A{
			bson.M{"auditProjectionPendingGeneration": bson.M{"$exists": true}},
			bson.M{"auditProjectionPendingEventCount": bson.M{"$gt": 0}},
		},
	}, options.FindOne().SetProjection(bson.M{"_id": 1})).Decode(&eventWorkProbe)
	if eventWorkProbeErr != nil && eventWorkProbeErr != mongo.ErrNoDocuments {
		return eventWorkProbeErr
	}
	shouldProbeEvents := eventWorkProbeErr == nil

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
		bson.M{"auditProjectionPendingEventCount": bson.M{"$gt": 0}},
	}}); err != nil {
		return err
	}
	if err := processStates(bson.M{"auditProjectionVersion": bson.M{"$ne": cwdAuditProjectionVersion}}); err != nil {
		return err
	}

	// A pending event is itself durable reconciliation work. It is intentionally
	// queried independently of source generations so an event committed after a
	// close writer has finished cannot disappear behind the newer generation.
	type pendingEvent struct{ id, sessionID string }
	pendingEvents := []pendingEvent{}
	if shouldProbeEvents {
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
			if sessionID := auditProjectionSessionID(event); eventID != "" && sessionID != "" {
				pendingEvents = append(pendingEvents, pendingEvent{id: eventID, sessionID: sessionID})
			}
		}
		if err := eventCursor.Err(); err != nil {
			eventCursor.Close(ctx)
			return err
		}
		if err := eventCursor.Close(ctx); err != nil {
			return err
		}
	}
	for _, pending := range pendingEvents {
		converged, err := mw.backfillCwdAuditProjectionSessionResult(ctx, pending.sessionID, retention)
		if err != nil {
			return err
		}
		if converged {
			state, err := mw.findCwdStateByCanonicalID(ctx, pending.sessionID)
			if err == mongo.ErrNoDocuments {
				continue
			}
			if err != nil {
				return err
			}
			if err := mw.clearCwdEventProjectionWork(ctx, state["_id"], pending.id); err != nil {
				return err
			}
		}
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
		{states, bson.M{"lifecycle.status": "closed", "$expr": validCwdAuditSourceExpression(), "auditProjectionPendingEventCount": bson.M{"$gt": 0}}, "CWD audit event ownership work did not converge"},
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
	if shouldProbeEvents {
		var pendingEvent bson.M
		if err := mw.db.Collection("cwd_events").FindOne(ctx, bson.M{"auditProjectionPending": true}, options.FindOne().SetProjection(bson.M{"_id": 1})).Decode(&pendingEvent); err != mongo.ErrNoDocuments {
			if err != nil {
				return err
			}
			return fmt.Errorf("CWD audit event work did not converge")
		}
	}
	_, err := mw.db.Collection("cwd_audit_projection_meta").UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$set": bson.M{"projectionVersion": cwdAuditProjectionVersion, "backfillCompletedAt": time.Now().UTC()}}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	log.Printf("CWD audit projection backfill complete")
	return nil
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
		}}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&claimed)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return claimed, err
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
