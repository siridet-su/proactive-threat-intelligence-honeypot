package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	cwdAuditProjectionCollection = "cwd_audit_projection"
	cwdAuditProjectionVersion    = "cwd_audit_projection.v1"
	cwdAuditProjectionMetaID     = "audit-directory"
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
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
}

func cwdStateIndexModels() []mongo.IndexModel {
	return []mongo.IndexModel{
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "updatedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "sessionId", Value: -1}}},
		{Keys: bson.D{{Key: "lifecycle.status", Value: 1}, {Key: "lifecycle.closedAt", Value: -1}, {Key: "session_id", Value: -1}}},
		{Keys: bson.D{{Key: "cwdState.path", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
}

func auditProjectionPathsExpression(paths ...string) bson.D {
	values := bson.A{}
	for _, path := range paths {
		values = append(values, path)
	}
	raw := bson.D{{Key: "$setUnion", Value: bson.A{
		bson.D{{Key: "$ifNull", Value: bson.A{"$auditVisitedPaths", bson.A{}}}},
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

func auditProjectionCurrentStateUpdate(observation cwdObservation, changed bool) mongo.Pipeline {
	if !changed {
		return nil
	}
	paths := auditProjectionPathsExpression(observation.Path)
	stage := bson.D{{Key: "$set", Value: bson.D{
		{Key: "sessionId", Value: observation.SessionID},
		{Key: "sourceIp", Value: observation.SourceIP},
		{Key: "cwdState", Value: bson.D{
			{Key: "path", Value: observation.Path},
			{Key: "status", Value: observation.Status},
			{Key: "observedAt", Value: observation.At},
			{Key: "sourceEventId", Value: observation.SourceEventID},
		}},
		{Key: "auditVisitedPaths", Value: paths},
		{Key: "auditHomeOnly", Value: auditProjectionHomeOnlyExpression(paths)},
		{Key: "auditProjectionVersion", Value: cwdAuditProjectionVersion},
		{Key: "updatedAt", Value: time.Now().UTC()},
	}}}
	return mongo.Pipeline{stage}
}

func auditProjectionEventUpdate(observation cwdObservation, eventID string) mongo.Pipeline {
	paths := auditProjectionPathsExpression(observation.FromPath, observation.Path)
	eventIDs := bson.D{{Key: "$setUnion", Value: bson.A{
		bson.D{{Key: "$ifNull", Value: bson.A{"$auditEventIds", bson.A{}}}},
		bson.A{eventID},
	}}}
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
		{Key: "auditVisitedPaths", Value: paths},
		{Key: "auditEventIds", Value: eventIDs},
		{Key: "auditEventCount", Value: bson.D{{Key: "$size", Value: eventIDs}}},
		{Key: "auditHomeOnly", Value: auditProjectionHomeOnlyExpression(paths)},
		{Key: "auditProjectionVersion", Value: cwdAuditProjectionVersion},
		{Key: "updatedAt", Value: time.Now().UTC()},
	}}}
	return mongo.Pipeline{stage}
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
		"auditVisitedPaths":      bson.A{},
		"auditEventIds":          bson.A{},
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

func (mw *MongoWriter) updateCwdAuditProjection(ctx context.Context, observation cwdObservation, eventID string, changed bool, retention time.Duration) error {
	if err := mw.seedCwdAuditProjection(ctx, observation, retention); err != nil {
		return err
	}
	collection := mw.db.Collection(cwdAuditProjectionCollection)
	if changed {
		if _, err := collection.UpdateOne(ctx, bson.M{"_id": observation.SessionID}, auditProjectionCurrentStateUpdate(observation, true)); err != nil {
			return err
		}
	}
	if eventID == "" {
		return nil
	}
	_, err := collection.UpdateOne(ctx, bson.M{"_id": observation.SessionID}, auditProjectionEventUpdate(observation, eventID))
	return err
}

func (mw *MongoWriter) closeCwdAuditProjection(ctx context.Context, sessionID string, closedAt time.Time, retention time.Duration) error {
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
				"schemaVersion":     cwdAuditProjectionVersion,
				"auditVisitedPaths": bson.A{},
				"auditEventIds":     bson.A{},
				"auditEventCount":   0,
				"auditHomeOnly":     false,
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
	history := mw.db.Collection("cwd_events")
	projection := mw.db.Collection(cwdAuditProjectionCollection)

	// Read compatibility is provided by the dashboard until this marker exists.
	// Backfill runs before the processor consumes new messages, so its source
	// population is stable; subsequent events converge through the idempotent
	// update path above.
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
		visited := bson.A{}
		if cwdState, ok := state["cwdState"].(bson.M); ok {
			if path, ok := cwdState["path"].(string); ok && strings.HasPrefix(path, "/") {
				visited = append(visited, path)
			}
		}
		eventIDs := bson.A{}
		historyCursor, findErr := history.Find(ctx, bson.M{"$or": bson.A{bson.M{"sessionId": sessionID}, bson.M{"session_id": sessionID}}, "action": bson.M{"$in": bson.A{"entered", "changed", "failed_change"}}}, options.Find().SetProjection(bson.M{"_id": 1, "eventId": 1, "fromPath": 1, "toPath": 1, "action": 1}))
		if findErr != nil {
			return findErr
		}
		for historyCursor.Next(ctx) {
			var event bson.M
			if err := historyCursor.Decode(&event); err != nil {
				historyCursor.Close(ctx)
				return err
			}
			eventID, _ := event["eventId"].(string)
			if strings.TrimSpace(eventID) == "" {
				eventID = fmt.Sprint(event["_id"])
			}
			if eventID != "" {
				eventIDs = append(eventIDs, eventID)
			}
			for _, field := range []string{"fromPath", "toPath"} {
				if value, ok := event[field].(string); ok && strings.HasPrefix(value, "/") && (event["action"] != "failed_change" || field != "toPath") {
					visited = append(visited, value)
				}
			}
		}
		historyCursor.Close(ctx)
		visited = uniqueStrings(visited)
		eventIDs = uniqueStrings(eventIDs)
		lifecycle, _ := state["lifecycle"].(bson.M)
		update := bson.M{
			"$set": bson.M{
				"schemaVersion":          cwdAuditProjectionVersion,
				"sessionId":              sessionID,
				"sourceIp":               state["sourceIp"],
				"cwdState":               state["cwdState"],
				"lifecycle":              lifecycle,
				"auditVisitedPaths":      visited,
				"auditEventIds":          eventIDs,
				"auditEventCount":        len(eventIDs),
				"auditHomeOnly":          auditHomeOnly(visited),
				"auditProjectionVersion": cwdAuditProjectionVersion,
				"updatedAt":              time.Now().UTC(),
				"expires_at":             state["expires_at"],
			},
		}
		if _, err := projection.UpdateOne(ctx, bson.M{"_id": sessionID}, update, options.Update().SetUpsert(true)); err != nil {
			return err
		}
		if _, err := states.UpdateOne(ctx, bson.M{"_id": state["_id"]}, bson.M{"$set": bson.M{"auditProjectionVersion": cwdAuditProjectionVersion}}); err != nil {
			return err
		}
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	_, err = mw.db.Collection("cwd_audit_projection_meta").UpdateOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}, bson.M{"$set": bson.M{"projectionVersion": cwdAuditProjectionVersion, "backfillCompletedAt": time.Now().UTC()}}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	log.Printf("CWD audit projection backfill complete")
	return nil
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
