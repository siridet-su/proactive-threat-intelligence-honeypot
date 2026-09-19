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
	cwdAuditProjectionVersion    = "cwd_audit_projection.v1"
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

func auditProjectionCurrentStateUpdate(observation cwdObservation, changed bool, retention time.Duration) mongo.Pipeline {
	if !changed {
		return nil
	}
	currentPath := bson.D{{Key: "$map", Value: bson.D{{Key: "input", Value: bson.A{1}}, {Key: "as", Value: "ignored"}, {Key: "in", Value: observation.Path}}}}
	paths := auditProjectionVisitedPathsWithCurrentPath(currentPath)
	stage := bson.D{{Key: "$set", Value: bson.D{
		{Key: "sessionId", Value: observation.SessionID},
		{Key: "sourceIp", Value: observation.SourceIP},
		{Key: "stateSequence", Value: observation.At.UnixNano()},
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
		{Key: "updatedAt", Value: time.Now().UTC()},
	}}}
	return mongo.Pipeline{stage}
}

func auditProjectionEventUpdate(observation cwdObservation, eventID string, increment bool) mongo.Pipeline {
	transitionPaths := []string{observation.FromPath}
	if observation.Action != "failed_change" {
		transitionPaths = append(transitionPaths, observation.Path)
	}
	transitionSet := auditProjectionPathSetExpression("$auditTransitionPaths", transitionPaths...)
	boundedTransitionSet := auditProjectionBoundedPathsExpression(transitionSet)
	currentPath := bson.D{{Key: "$map", Value: bson.D{{Key: "input", Value: bson.A{1}}, {Key: "as", Value: "ignored"}, {Key: "in", Value: "$cwdState.path"}}}}
	visited := bson.D{{Key: "$setUnion", Value: bson.A{transitionSet, currentPath}}}
	visited = bson.D{{Key: "$filter", Value: bson.D{{Key: "input", Value: visited}, {Key: "as", Value: "path"}, {Key: "cond", Value: bson.D{{Key: "$and", Value: bson.A{bson.D{{Key: "$ne", Value: bson.A{"$$path", nil}}}, bson.D{{Key: "$ne", Value: bson.A{"$$path", ""}}}, bson.D{{Key: "$regexMatch", Value: bson.D{{Key: "input", Value: "$$path"}, {Key: "regex", Value: "^/"}}}}}}}}}}}
	stage := bson.D{{Key: "$set", Value: bson.D{
		// A close can be consumed before the first CWD event. The event is
		// still authoritative for the missing current path, but never replaces
		// an already-known state path or lifecycle status.
		{Key: "sessionId", Value: observation.SessionID},
		{Key: "sourceIp", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$sourceIp", observation.SourceIP}}}},
		{Key: "cwdState", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$cwdState", bson.D{
			{Key: "path", Value: observation.Path},
			{Key: "status", Value: observation.Status},
			{Key: "observedAt", Value: observation.At},
			{Key: "sourceEventId", Value: observation.SourceEventID},
		}}}}},
		{Key: "auditTransitionPaths", Value: boundedTransitionSet},
		{Key: "auditPathsOverflow", Value: bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$auditPathsOverflow", false}}}, auditProjectionOverflowExpression(transitionSet)}}}},
		{Key: "auditVisitedPaths", Value: visited},
		{Key: "auditHomeOnly", Value: auditProjectionHomeOnlyExpression(visited)},
		{Key: "auditEventCount", Value: bson.D{{Key: "$add", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$auditEventCount", 0}}}, boolInt(increment)}}}},
		{Key: "auditProjectionVersion", Value: cwdAuditProjectionVersion},
		{Key: "updatedAt", Value: time.Now().UTC()},
	}}}
	return mongo.Pipeline{stage}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (mw *MongoWriter) seedCwdAuditProjection(ctx context.Context, observation cwdObservation, retention time.Duration) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to seed CWD audit projection")
	}
	seed := bson.M{
		"schemaVersion":          cwdAuditProjectionVersion,
		"sessionId":              observation.SessionID,
		"sourceIp":               observation.SourceIP,
		"cwdState":               bson.M{"path": observation.Path, "status": observation.Status, "observedAt": observation.At, "sourceEventId": observation.SourceEventID},
		"auditTransitionPaths":   bson.A{},
		"auditVisitedPaths":      bson.A{observation.Path},
		"auditPathsOverflow":     false,
		"auditEventCount":        0,
		"auditHomeOnly":          false,
		"auditProjectionVersion": cwdAuditProjectionVersion,
		"lifecycle":              bson.M{"status": "active", "startedAt": observation.At},
		"updatedAt":              observation.At,
		"expires_at":             expiryAt(observation.At, retention),
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

func (mw *MongoWriter) updateCwdAuditProjection(ctx context.Context, observation cwdObservation, eventID string, changed bool, eventInserted bool, retention time.Duration) error {
	if err := mw.seedCwdAuditProjection(ctx, observation, retention); err != nil {
		return err
	}
	collection := mw.db.Collection(cwdAuditProjectionCollection)
	if changed {
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": observation.SessionID}, auditProjectionCurrentStateUpdate(observation, true, retention)); err != nil {
			return err
		}
	}
	if eventID == "" {
		return nil
	}
	if !eventInserted {
		// A retry after a crash may observe the durable event but not the
		// projection write. Reconcile from source history before the idempotent
		// no-op event update; this preserves recovery without an event-id array.
		if err := mw.backfillCwdAuditProjectionSession(ctx, observation.SessionID, retention); err != nil {
			return err
		}
	}
	_, err := collection.UpdateOne(ctx, bson.M{"_id": observation.SessionID}, auditProjectionEventUpdate(observation, eventID, eventInserted))
	return err
}

func (mw *MongoWriter) closeCwdAuditProjection(ctx context.Context, sessionID string, closedAt time.Time, retention time.Duration) error {
	if err := mw.backfillCwdAuditProjectionSession(ctx, sessionID, retention); err != nil {
		return err
	}
	_, err := mw.db.Collection(cwdAuditProjectionCollection).UpdateOne(
		ctx,
		bson.M{"_id": sessionID},
		bson.M{
			"$set": bson.M{
				"sessionId":              sessionID,
				"lifecycle.status":       "closed",
				"lifecycle.closedAt":     closedAt,
				"updatedAt":              closedAt,
				"expires_at":             expiryAt(closedAt, retention),
				"auditProjectionVersion": cwdAuditProjectionVersion,
			},
			"$setOnInsert": bson.M{
				"schemaVersion":        cwdAuditProjectionVersion,
				"auditTransitionPaths": bson.A{},
				"auditVisitedPaths":    bson.A{},
				"auditPathsOverflow":   false,
				"auditEventCount":      0,
				"auditHomeOnly":        false,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
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
	cursor, err := states.Find(ctx, bson.M{
		"lifecycle.status":       "closed",
		"auditProjectionVersion": bson.M{"$ne": cwdAuditProjectionVersion},
	})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var state bson.M
		if err := cursor.Decode(&state); err != nil {
			return err
		}
		sessionID := auditProjectionSessionID(state)
		if sessionID == "" {
			continue
		}
		if err := mw.backfillCwdAuditProjectionState(ctx, state, retention); err != nil {
			return err
		}
		if _, err := states.UpdateOne(ctx, bson.M{"_id": state["_id"]}, bson.M{"$set": bson.M{"auditProjectionVersion": cwdAuditProjectionVersion}}); err != nil {
			return err
		}
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	missing, err := states.CountDocuments(ctx, bson.M{"lifecycle.status": "closed", "auditProjectionVersion": bson.M{"$ne": cwdAuditProjectionVersion}})
	if err != nil {
		return err
	}
	if missing != 0 {
		return fmt.Errorf("CWD audit projection backfill did not converge: %d source states remain", missing)
	}
	_, err = mw.db.Collection("cwd_audit_projection_meta").UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$set": bson.M{"projectionVersion": cwdAuditProjectionVersion, "backfillCompletedAt": time.Now().UTC()}}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	log.Printf("CWD audit projection backfill complete")
	return nil
}

func (mw *MongoWriter) backfillCwdAuditProjectionSession(ctx context.Context, sessionID string, retention time.Duration) error {
	var state bson.M
	err := mw.db.Collection("cwd_session_state").FindOne(ctx, bson.M{"$or": bson.A{bson.M{"_id": sessionID}, bson.M{"sessionId": sessionID}, bson.M{"session_id": sessionID}}}).Decode(&state)
	if err == mongo.ErrNoDocuments {
		return nil
	}
	if err != nil {
		return err
	}
	return mw.backfillCwdAuditProjectionState(ctx, state, retention)
}

func (mw *MongoWriter) backfillCwdAuditProjectionState(ctx context.Context, state bson.M, retention time.Duration) error {
	sessionID := auditProjectionSessionID(state)
	if sessionID == "" {
		return nil
	}
	transitionPaths := bson.A{}
	ids := bson.A{}
	statePath := ""
	if cwdState, ok := state["cwdState"].(bson.M); ok {
		statePath, _ = cwdState["path"].(string)
	}
	historyCursor, err := mw.db.Collection("cwd_events").Find(ctx, bson.M{"$or": bson.A{bson.M{"sessionId": sessionID}, bson.M{"session_id": sessionID}}, "action": bson.M{"$in": bson.A{"entered", "changed", "failed_change"}}}, options.Find().SetProjection(bson.M{"_id": 1, "eventId": 1, "fromPath": 1, "toPath": 1, "action": 1}))
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
		ids = append(ids, id)
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
	if err := historyCursor.Close(ctx); err != nil {
		return err
	}
	transitionPaths, ids = uniqueStrings(transitionPaths), uniqueStrings(ids)
	lifecycle, _ := state["lifecycle"].(bson.M)
	filter := bson.M{"_id": sessionID}
	if sequence, ok := state["stateSequence"]; ok {
		filter["$or"] = bson.A{bson.M{"stateSequence": bson.M{"$exists": false}}, bson.M{"stateSequence": bson.M{"$lte": sequence}}}
	}
	projection := mw.db.Collection(cwdAuditProjectionCollection)
	if _, err := projection.UpdateOne(ctx, bson.M{"_id": sessionID}, bson.M{"$setOnInsert": bson.M{"_id": sessionID, "auditTransitionPaths": bson.A{}, "auditEventCount": 0}}, options.Update().SetUpsert(true)); err != nil {
		return err
	}
	transitionExpr := bson.M{"$setUnion": bson.A{bson.M{"$ifNull": bson.A{"$auditTransitionPaths", bson.A{}}}, transitionPaths}}
	boundedTransitionExpr := bson.M{"$slice": bson.A{transitionExpr, cwdAuditProjectionMaxPaths}}
	currentPath := bson.M{"$map": bson.M{"input": bson.A{1}, "as": "ignored", "in": statePath}}
	visitedExpr := bson.M{"$filter": bson.M{"input": bson.M{"$setUnion": bson.A{boundedTransitionExpr, currentPath}}, "as": "path", "cond": bson.M{"$and": bson.A{bson.M{"$ne": bson.A{"$$path", nil}}, bson.M{"$ne": bson.A{"$$path", ""}}, bson.M{"$regexMatch": bson.M{"input": "$$path", "regex": "^/"}}}}}}
	countExpr := bson.M{"$cond": bson.A{bson.M{"$gt": bson.A{len(ids), bson.M{"$ifNull": bson.A{"$auditEventCount", 0}}}}, len(ids), bson.M{"$ifNull": bson.A{"$auditEventCount", 0}}}}
	set := bson.M{"schemaVersion": cwdAuditProjectionVersion, "sessionId": sessionID, "sourceIp": state["sourceIp"], "cwdState": state["cwdState"], "lifecycle": lifecycle, "auditTransitionPaths": boundedTransitionExpr, "auditPathsOverflow": bson.M{"$or": bson.A{bson.M{"$ifNull": bson.A{"$auditPathsOverflow", false}}, bson.M{"$gt": bson.A{bson.M{"$size": transitionExpr}, cwdAuditProjectionMaxPaths}}}}, "auditVisitedPaths": visitedExpr, "auditEventCount": countExpr, "auditProjectionVersion": cwdAuditProjectionVersion, "updatedAt": time.Now().UTC(), "expires_at": stateExpiry(state, retention)}
	if _, err := projection.UpdateOne(ctx, filter, mongo.Pipeline{{{Key: "$set", Value: set}}}); err != nil {
		return err
	}
	// The public classification is derived from the merged expression so a
	// concurrent event cannot be lost by a backfill write.
	_, err = projection.UpdateOne(ctx, bson.M{"_id": sessionID}, mongo.Pipeline{{{Key: "$set", Value: bson.M{"auditHomeOnly": auditProjectionHomeOnlyExpression(bson.M{"$ifNull": bson.A{"$auditVisitedPaths", bson.A{}}})}}}})
	if err != nil {
		return err
	}
	_, err = mw.db.Collection("cwd_session_state").UpdateOne(ctx, bson.M{"_id": state["_id"]}, bson.M{"$set": bson.M{"auditProjectionVersion": cwdAuditProjectionVersion}})
	return err
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
	default:
		return time.Time{}, false
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
