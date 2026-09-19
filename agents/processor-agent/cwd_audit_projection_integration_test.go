package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestFA016AuditProjectionIntegration(t *testing.T) {
	uri := os.Getenv("FA016_MONGO_URI")
	databaseName := os.Getenv("FA016_MONGO_DB")
	runID := os.Getenv("FA016_MONGO_RUN_ID")
	if uri == "" && databaseName == "" && runID == "" {
		t.Skip("FA016_MONGO_URI is not set")
	}
	target, err := validateFA016MongoTarget(uri, databaseName, runID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cwdEventFinds int
	monitor := &event.CommandMonitor{Started: func(_ context.Context, started *event.CommandStartedEvent) {
		if cwdEventHistoryFind(started) {
			cwdEventFinds++
		}
	}}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI).SetMonitor(monitor))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate a rolling deployment that left the right key pattern with the
	// retired TTL option. The authoritative owner must remove it.
	if _, err := db.Collection(cwdAuditProjectionCollection).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}}); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}

	// Keep the retained fixtures ahead of the wall clock. Source rows remain
	// TTL-retained; projection expiry is only a source-owned cleanup watermark.
	closedAt := time.Date(2026, 9, 19, 23, 0, 0, 0, time.UTC)
	const v1ProjectionVersion = "cwd_audit_projection.v1"
	_, err = db.Collection("cwd_session_state").InsertMany(ctx, []any{
		bson.M{
			"_id": "canonical-session", "sessionId": "canonical-session", "sourceIp": "198.51.100.10",
			"cwdState":  bson.M{"path": "/home/cowrie", "status": "confirmed"},
			"lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour), "auditProjectionVersion": v1ProjectionVersion,
		},
		bson.M{
			"_id": "legacy-state-id", "session_id": "legacy-session", "sourceIp": "198.51.100.11",
			"cwdState":  bson.M{"path": "/var/tmp", "status": "observed"},
			"lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour), "auditProjectionVersion": v1ProjectionVersion,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection(cwdAuditProjectionCollection).InsertMany(ctx, []any{
		bson.M{"_id": "canonical-session", "sessionId": "canonical-session", "cwdState": bson.M{"path": "/home/cowrie"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditVisitedPaths": bson.A{"/home/cowrie", "/etc"}, "auditEventIds": bson.A{"canonical-event"}, "auditEventCount": 1, "auditHomeOnly": false, "auditProjectionVersion": v1ProjectionVersion, "expires_at": closedAt.Add(time.Hour)},
		bson.M{"_id": "legacy-session", "sessionId": "legacy-session", "cwdState": bson.M{"path": "/var/tmp"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditVisitedPaths": bson.A{"/var/tmp"}, "auditEventIds": bson.A{"legacy-event"}, "auditEventCount": 1, "auditHomeOnly": false, "auditProjectionVersion": v1ProjectionVersion, "expires_at": closedAt.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("cwd_audit_projection_meta").InsertOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID, "projectionVersion": v1ProjectionVersion, "backfillCompletedAt": closedAt}); err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection("cwd_events").InsertMany(ctx, []any{
		bson.M{"_id": "canonical-event", "eventId": "canonical-event", "sessionId": "canonical-session", "action": "changed", "fromPath": "/home/cowrie", "toPath": "/etc", "at": closedAt},
		bson.M{"_id": "legacy-event", "eventId": "legacy-event", "session_id": "legacy-session", "action": "changed", "fromPath": "/var/tmp", "toPath": "/opt", "timestamp": closedAt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}

	projection := db.Collection(cwdAuditProjectionCollection)
	for _, sessionID := range []string{"canonical-session", "legacy-session"} {
		doc := bson.M{}
		if err := projection.FindOne(ctx, bson.M{"_id": sessionID}).Decode(&doc); err != nil {
			t.Fatalf("projection %s missing: %v", sessionID, err)
		}
		if doc["sessionId"] != sessionID || doc["auditProjectionVersion"] != cwdAuditProjectionVersion {
			t.Fatalf("projection %s is not canonical/read-ready: %#v", sessionID, doc)
		}
		if _, exists := doc["auditEventIds"]; exists {
			t.Fatalf("projection %s retained obsolete unbounded v1 auditEventIds: %#v", sessionID, doc)
		}
	}
	meta := bson.M{}
	if err := db.Collection("cwd_audit_projection_meta").FindOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID}).Decode(&meta); err != nil || meta["projectionVersion"] != cwdAuditProjectionVersion {
		t.Fatalf("v1 readiness marker was not replaced only after v2 migration: %#v err=%v", meta, err)
	}

	lateSession := "late-session"
	lateClosedAt := closedAt.Add(time.Minute)
	if err := mw.closeCwdSession(ctx, lateSession, lateClosedAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	lateObservation := cwdObservation{
		SessionID: lateSession, SourceIP: "198.51.100.12", SourceEventID: "late-source",
		At: lateClosedAt.Add(time.Second), FromPath: "/home/cowrie", Path: "/etc/shadow", Action: "changed", Status: "confirmed",
	}
	if err := mw.recordCwdObservation(ctx, lateObservation, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Same source event ID, deliberately different retry payload: persisted
	// cwd_events truth must win over the untrusted duplicate payload.
	lateRetry := lateObservation
	lateRetry.FromPath = "/untrusted-from"
	lateRetry.Path = "/untrusted-target"
	if err := mw.recordCwdObservation(ctx, lateRetry, time.Hour); err != nil {
		t.Fatal(err)
	}
	late := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": lateSession}).Decode(&late); err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := late["lifecycle"].(bson.M)
	if lifecycle["status"] != "closed" {
		t.Fatalf("late history revived closed projection: %#v", late)
	}
	if !testBSONTime(late["expires_at"]).Equal(lateClosedAt.Add(time.Hour)) {
		t.Fatalf("late history extended closed retention boundary: %#v", late["expires_at"])
	}
	if late["auditEventCount"] != int32(1) && late["auditEventCount"] != int64(1) {
		t.Fatalf("duplicate event was not idempotent: %#v", late["auditEventCount"])
	}
	var eventCount int64
	eventCount, err = db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:late-source"})
	if err != nil || eventCount != 1 {
		t.Fatalf("event retry was not idempotent count=%d err=%v", eventCount, err)
	}
	var visited []string
	if raw, ok := late["auditVisitedPaths"].(bson.A); ok {
		for _, value := range raw {
			if path, ok := value.(string); ok {
				visited = append(visited, path)
			}
		}
	}
	if !containsString(visited, "/etc/shadow") || !containsString(visited, "/home/cowrie") {
		t.Fatalf("late history did not converge into visited paths: %#v", visited)
	}
	if containsString(visited, "/untrusted-target") || containsString(visited, "/untrusted-from") {
		t.Fatalf("duplicate retry payload overrode persisted event truth: %#v", visited)
	}

	indexCursor, err := projection.Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var indexes []bson.M
	if err := indexCursor.All(ctx, &indexes); err != nil {
		t.Fatal(err)
	}
	foundProjectionExpiryIndex := false
	for _, index := range indexes {
		if index["name"] == "expires_at_1" && index["expireAfterSeconds"] == nil {
			foundProjectionExpiryIndex = true
		}
	}
	if !foundProjectionExpiryIndex {
		t.Fatalf("projection cleanup watermark index was not provisioned without TTL: %#v", indexes)
	}

	base := closedAt.Add(2 * time.Hour)
	observedOnly := "observed-only"
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: observedOnly, SourceEventID: "observed-1", At: base, Path: "/etc", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: observedOnly, SourceEventID: "observed-2", At: base.Add(time.Minute), Path: "/home/cowrie", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	activeObservedDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": observedOnly}).Decode(&activeObservedDoc); err != nil {
		t.Fatal(err)
	}
	if got := stringSlice(activeObservedDoc["auditVisitedPaths"]); len(got) != 1 || got[0] != "/home/cowrie" || activeObservedDoc["auditHomeOnly"] != true {
		t.Fatalf("active observed-only projection changed legacy semantics: %#v", activeObservedDoc)
	}
	if err := mw.closeCwdSession(ctx, observedOnly, base.Add(2*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	observedDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": observedOnly}).Decode(&observedDoc); err != nil {
		t.Fatal(err)
	}
	if got := stringSlice(observedDoc["auditVisitedPaths"]); len(got) != 1 || got[0] != "/home/cowrie" || observedDoc["auditHomeOnly"] != true {
		t.Fatalf("observed-only projection changed legacy semantics: %#v", observedDoc)
	}

	paritySession := "parity-session"
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: paritySession, SourceEventID: "parity-observed", At: base, Path: "/home/cowrie", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: paritySession, SourceEventID: "parity-change", At: base.Add(time.Minute), FromPath: "/home/cowrie", Path: "/etc", Action: "changed", Status: "confirmed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: paritySession, SourceEventID: "parity-failed", At: base.Add(2 * time.Minute), FromPath: "/etc", Path: "/etc", Action: "failed_change", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := mw.closeCwdSession(ctx, paritySession, base.Add(3*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	parityDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": paritySession}).Decode(&parityDoc); err != nil {
		t.Fatal(err)
	}
	paths := stringSlice(parityDoc["auditVisitedPaths"])
	if !containsString(paths, "/home/cowrie") || !containsString(paths, "/etc") || containsString(paths, "/opt/never-visited") {
		t.Fatalf("transition/current parity failed: %#v", parityDoc)
	}

	retentionSession := "retention-session"
	firstAt := base.Add(10 * time.Hour)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: retentionSession, SourceEventID: "retention-first", At: firstAt, Path: "/home/cowrie", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: retentionSession, SourceEventID: "retention-new", At: firstAt.Add(2 * time.Hour), Path: "/home/cowrie", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	retentionDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": retentionSession}).Decode(&retentionDoc); err != nil {
		t.Fatal(err)
	}
	newExpiry := testBSONTime(retentionDoc["expires_at"])
	if !newExpiry.Equal(firstAt.Add(3 * time.Hour)) {
		t.Fatalf("accepted active observation did not advance expiry: %v", newExpiry)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: retentionSession, SourceEventID: "retention-stale", At: firstAt.Add(time.Hour), Path: "/etc", Action: "observed", Status: "observed"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	retentionDoc = bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": retentionSession}).Decode(&retentionDoc); err != nil {
		t.Fatal(err)
	}
	if !testBSONTime(retentionDoc["expires_at"]).Equal(newExpiry) || stringSlice(retentionDoc["auditVisitedPaths"])[0] != "/home/cowrie" {
		t.Fatalf("stale observation moved projection backward: %#v", retentionDoc)
	}
	if _, err := projection.DeleteOne(ctx, bson.M{"_id": retentionSession}); err != nil {
		t.Fatal(err)
	}
	if err := mw.closeCwdSession(ctx, retentionSession, firstAt.Add(3*time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := projection.FindOne(ctx, bson.M{"_id": retentionSession}).Decode(&retentionDoc); err != nil {
		t.Fatalf("close did not reconstruct deleted projection: %v", err)
	}
	if !testBSONTime(retentionDoc["expires_at"]).Equal(firstAt.Add(4 * time.Hour)) {
		t.Fatalf("close reconstruction used wrong retention boundary: %#v", retentionDoc)
	}

	legacyExpiry := "legacy-missing-expiry"
	if _, err := db.Collection("cwd_session_state").InsertOne(ctx, bson.M{"_id": legacyExpiry, "session_id": legacyExpiry, "cwdState": bson.M{"path": "/home/cowrie"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	legacyDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": legacyExpiry}).Decode(&legacyDoc); err != nil {
		t.Fatal(err)
	}
	if !testBSONTime(legacyDoc["expires_at"]).Equal(closedAt.Add(time.Hour)) {
		t.Fatalf("missing expiry was not bounded from close time: %#v", legacyDoc)
	}

	boundedSession := "bounded-history-session"
	if _, err := db.Collection("cwd_session_state").InsertOne(ctx, bson.M{"_id": boundedSession, "sessionId": boundedSession, "cwdState": bson.M{"path": "/home/current"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour), "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)}); err != nil {
		t.Fatal(err)
	}
	events := make([]any, 0, cwdAuditProjectionMaxPaths+32)
	for index := 0; index < cwdAuditProjectionMaxPaths+32; index++ {
		events = append(events, bson.M{"_id": fmt.Sprintf("bounded-event-%d", index), "eventId": fmt.Sprintf("bounded-event-%d", index), "sessionId": boundedSession, "action": "changed", "fromPath": fmt.Sprintf("/var/path-%d", index), "toPath": fmt.Sprintf("/opt/path-%d", index), "at": closedAt})
	}
	if _, err := db.Collection("cwd_events").InsertMany(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	boundedDoc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": boundedSession}).Decode(&boundedDoc); err != nil {
		t.Fatal(err)
	}
	if len(stringSlice(boundedDoc["auditTransitionPaths"])) > cwdAuditProjectionMaxPaths || boundedDoc["auditPathsOverflow"] != true {
		t.Fatalf("projection history storage was not bounded: %#v", boundedDoc)
	}
	cwdEventFinds = 0
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if cwdEventFinds != 0 {
		t.Fatalf("steady-state reconciliation read cwd_events for already-converged rows: %d", cwdEventFinds)
	}
}

func TestFA016ProjectionOrderingInterleavings(t *testing.T) {
	uri := os.Getenv("FA016_MONGO_URI")
	databaseName := os.Getenv("FA016_MONGO_DB")
	runID := os.Getenv("FA016_MONGO_RUN_ID")
	if uri == "" && databaseName == "" && runID == "" {
		t.Skip("FA016_MONGO_URI is not set")
	}
	target, err := validateFA016MongoTarget(uri, databaseName, runID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 19, 23, 30, 0, 0, time.UTC)
	newer := cwdObservation{SessionID: "interleaved", SourceIP: "198.51.100.2", SourceEventID: "event-z", At: base.Add(2 * time.Minute), FromPath: "/old", Path: "/new", Action: "changed", Status: "confirmed"}
	older := cwdObservation{SessionID: "interleaved", SourceIP: "198.51.100.1", SourceEventID: "event-a", At: base, FromPath: "/old", Path: "/oldest", Action: "changed", Status: "confirmed"}
	newerStateWritten := make(chan struct{})
	releaseNewerProjection := make(chan struct{})
	var stateBarrierStarted atomic.Bool
	mw.auditAfterCwdStateUpdate = func() {
		if stateBarrierStarted.CompareAndSwap(false, true) {
			close(newerStateWritten)
			<-releaseNewerProjection
		}
	}
	newerFinished := make(chan error, 1)
	oldFinished := make(chan error, 1)
	go func() { newerFinished <- mw.recordCwdObservation(ctx, newer, retention) }()
	<-newerStateWritten
	go func() {
		oldFinished <- mw.recordCwdObservation(ctx, older, retention)
	}()
	if err := <-oldFinished; err != nil {
		t.Fatal(err)
	}
	close(releaseNewerProjection)
	if err := <-newerFinished; err != nil {
		t.Fatal(err)
	}
	projection := db.Collection(cwdAuditProjectionCollection)
	doc := bson.M{}
	if err := projection.FindOne(ctx, bson.M{"_id": "interleaved"}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	cwdState, _ := doc["cwdState"].(bson.M)
	if cwdState["path"] != "/new" || doc["stateSourceEventId"] != "event-z" {
		t.Fatalf("delayed older projection downgraded current state: %#v", doc)
	}

	tieHigh := newer
	tieHigh.SourceEventID = "tie-z"
	tieHigh.At = base.Add(4 * time.Minute)
	tieHigh.Path = "/tie-new"
	tieLow := tieHigh
	tieLow.SourceEventID = "tie-a"
	tieLow.Path = "/tie-old"
	if err := mw.recordCwdObservation(ctx, tieHigh, retention); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, tieLow, retention); err != nil {
		t.Fatal(err)
	}
	if err := projection.FindOne(ctx, bson.M{"_id": "interleaved"}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	cwdState, _ = doc["cwdState"].(bson.M)
	if cwdState["path"] != "/tie-new" || doc["stateSourceEventId"] != "tie-z" {
		t.Fatalf("equal timestamp source-event ordering was not monotonic: %#v", doc)
	}

	closedAt := base.Add(10 * time.Minute)
	if err := mw.closeCwdSession(ctx, "interleaved", closedAt, retention); err != nil {
		t.Fatal(err)
	}
	closedExpiry := testBSONTime((func() any {
		var value bson.M
		_ = projection.FindOne(ctx, bson.M{"_id": "interleaved"}).Decode(&value)
		return value["expires_at"]
	})())
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "interleaved", SourceIP: "198.51.100.0", SourceEventID: "late-active", At: closedAt.Add(-time.Minute), Path: "/late", FromPath: "/tie-new", Action: "changed", Status: "confirmed"}, retention); err != nil {
		t.Fatal(err)
	}
	if err := projection.FindOne(ctx, bson.M{"_id": "interleaved"}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	cwdState, _ = doc["cwdState"].(bson.M)
	lifecycle, _ := doc["lifecycle"].(bson.M)
	if cwdState["path"] != "/tie-new" || lifecycle["status"] != "closed" || !testBSONTime(doc["expires_at"]).Equal(closedExpiry) || doc["sourceIp"] != "198.51.100.2" {
		t.Fatalf("close did not win against delayed active projection: %#v", doc)
	}

	// A backfill snapshot captured before close is deliberately applied after
	// close. Its ordering and lifecycle guards must make it a no-op.
	staleState := bson.M{
		"_id": "interleaved", "sessionId": "interleaved", "sourceIp": "198.51.100.99",
		"stateSequence": older.At.UnixNano(), "stateSourceEventId": older.SourceEventID,
		"cwdState": bson.M{"path": "/stale-backfill"}, "lifecycle": bson.M{"status": "active", "startedAt": older.At},
	}
	if err := mw.backfillCwdAuditProjectionState(ctx, staleState, retention); err != nil {
		t.Fatal(err)
	}
	if err := projection.FindOne(ctx, bson.M{"_id": "interleaved"}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	cwdState, _ = doc["cwdState"].(bson.M)
	lifecycle, _ = doc["lifecycle"].(bson.M)
	if cwdState["path"] != "/tie-new" || lifecycle["status"] != "closed" || doc["sourceIp"] != "198.51.100.2" || !testBSONTime(doc["expires_at"]).Equal(closedExpiry) {
		t.Fatalf("stale active backfill crossed the close boundary: %#v", doc)
	}
}

func TestFA016BackfillHistoryRevisionBarrier(t *testing.T) {
	uri := os.Getenv("FA016_MONGO_URI")
	databaseName := os.Getenv("FA016_MONGO_DB")
	runID := os.Getenv("FA016_MONGO_RUN_ID")
	if uri == "" && databaseName == "" && runID == "" {
		t.Skip("FA016_MONGO_URI is not set")
	}
	target, err := validateFA016MongoTarget(uri, databaseName, runID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	// The current state is newer than both retained history events. The first
	// backfill snapshot is held after its cwd_events read, then the late event
	// is durably inserted and projected before the snapshot resumes.
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "history-race", SourceEventID: "state-current", At: base.Add(2 * time.Minute), Path: "/current", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "history-race", SourceEventID: "history-initial", At: base, FromPath: "/home/cowrie", Path: "/initial", Action: "changed", Status: "confirmed"}, retention); err != nil {
		t.Fatal(err)
	}
	readComplete := make(chan struct{})
	resume := make(chan struct{})
	var barrierStarted atomic.Bool
	mw.auditBackfillAfterHistoryRead = func() {
		if barrierStarted.CompareAndSwap(false, true) {
			close(readComplete)
			<-resume
		}
	}
	backfillDone := make(chan error, 1)
	go func() {
		backfillDone <- mw.backfillCwdAuditProjectionState(ctx, bson.M{"_id": "history-race", "sessionId": "history-race", "stateSequence": base.Add(2 * time.Minute).UnixNano(), "stateSourceEventId": "state-current", "cwdState": bson.M{"path": "/current"}, "lifecycle": bson.M{"status": "active", "startedAt": base}}, retention)
	}()
	<-readComplete
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "history-race", SourceEventID: "history-late", At: base.Add(time.Minute), FromPath: "/initial", Path: "/late", Action: "changed", Status: "confirmed"}, retention); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-backfillDone; err != nil {
		t.Fatal(err)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "history-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if count := bsonInt64(projection["auditEventCount"]); count != 2 {
		t.Fatalf("delayed backfill overwrote newer exact history count: %#v", projection)
	}
	paths := stringSlice(projection["auditTransitionPaths"])
	if !containsString(paths, "/late") || !containsString(paths, "/initial") {
		t.Fatalf("delayed backfill lost the late event path: %#v", projection)
	}
}

func TestFA016GenerationOwnedReadinessRace(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "generation-race", SourceEventID: "initial", At: base, Path: "/initial", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}

	firstStateWritten := make(chan struct{})
	releaseOlder := make(chan struct{})
	var firstBarrier atomic.Bool
	mw.auditAfterCwdStateUpdate = func() {
		if firstBarrier.CompareAndSwap(false, true) {
			close(firstStateWritten)
			<-releaseOlder
		}
	}
	olderDone := make(chan error, 1)
	go func() {
		olderDone <- mw.recordCwdObservation(ctx, cwdObservation{SessionID: "generation-race", SourceEventID: "older", At: base.Add(time.Minute), Path: "/older", Action: "observed", Status: "observed"}, retention)
	}()
	<-firstStateWritten
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "generation-race", SourceEventID: "newer", At: base.Add(2 * time.Minute), Path: "/newer", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	close(releaseOlder)
	if err := <-olderDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdStateUpdate = nil

	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "generation-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending {
		t.Fatalf("older writer cleared newer pending generation: %#v", state)
	}
	if bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
		t.Fatalf("source readiness is not generation-owned: %#v", state)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "generation-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	cwdState, _ := projection["cwdState"].(bson.M)
	if cwdState["path"] != "/newer" {
		t.Fatalf("older writer downgraded the projection after newer work completed: %#v", projection)
	}

	// Simulate writer B crashing after it owns a newer pending generation but
	// before its projection write. Reconciliation must claim only that source
	// generation and repair it from source/history truth.
	if err := mw.closeCwdSession(ctx, "generation-race", base.Add(3*time.Minute), retention); err != nil {
		t.Fatal(err)
	}
	if _, err := mw.advanceCwdProjectionGeneration(ctx, "generation-race"); err != nil {
		t.Fatal(err)
	}
	if err := mw.markCwdAuditSourceReady(ctx, "generation-race", 1); err != nil {
		t.Fatal(err)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "generation-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; !pending {
		t.Fatal("older writer incorrectly cleared newer crash-pending generation")
	}
	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "generation-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
		t.Fatalf("reconciliation did not clear only the matching generation: %#v", state)
	}
}

func TestFA016HistoryCrashBoundariesAndDuplicateRetry(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "stale-history", SourceEventID: "initial", At: base, Path: "/current", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	if err := mw.closeCwdSession(ctx, "stale-history", base.Add(time.Minute), retention); err != nil {
		t.Fatal(err)
	}

	eventWritten := make(chan struct{})
	releaseProjection := make(chan struct{})
	var barrierOnce sync.Once
	mw.auditAfterCwdEventWrite = func() {
		barrierOnce.Do(func() {
			close(eventWritten)
			<-releaseProjection
		})
	}
	staleDone := make(chan error, 1)
	go func() {
		staleDone <- mw.recordCwdObservation(ctx, cwdObservation{SessionID: "stale-history", SourceEventID: "stale", At: base.Add(-time.Minute), FromPath: "/current", Path: "/stale", Action: "changed", Status: "confirmed"}, retention)
	}()
	<-eventWritten
	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "stale-history"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; !pending {
		t.Fatalf("stale event was persisted without durable pending projection work: %#v", state)
	}
	if count, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:stale"}); err != nil || count != 1 {
		t.Fatalf("stale event did not persist before the projection barrier count=%d err=%v", count, err)
	}
	// The source is closed, so reconciliation can repair the persisted event
	// while the original writer is still stopped before its projection write.
	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}
	close(releaseProjection)
	if err := <-staleDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdEventWrite = nil

	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "stale-history"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(stringSlice(projection["auditVisitedPaths"]), "/stale") {
		t.Fatalf("reconciliation did not restore exact stale-event paths/count: %#v", projection)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "stale-history"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
		t.Fatalf("stale-event reconciliation left generation state dirty: %#v", state)
	}

	accepted := cwdObservation{SessionID: "accepted-history", SourceEventID: "accepted", At: base.Add(2 * time.Minute), FromPath: "/current", Path: "/accepted", Action: "changed", Status: "confirmed"}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: accepted.SessionID, SourceEventID: "initial", At: base, Path: "/current", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	barrierOnce = sync.Once{}
	eventWritten = make(chan struct{})
	releaseProjection = make(chan struct{})
	mw.auditAfterCwdEventWrite = func() {
		barrierOnce.Do(func() {
			close(eventWritten)
			<-releaseProjection
		})
	}
	acceptedDone := make(chan error, 1)
	go func() { acceptedDone <- mw.recordCwdObservation(ctx, accepted, retention) }()
	<-eventWritten
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": accepted.SessionID}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; !pending {
		t.Fatalf("accepted event did not establish pending generation: %#v", state)
	}
	close(releaseProjection)
	if err := <-acceptedDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdEventWrite = nil
	// Inspect the first accepted delivery before any duplicate retry. The
	// durable event outbox must already have produced the exact history facts.
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": accepted.SessionID}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(stringSlice(projection["auditTransitionPaths"]), "/current") || !containsString(stringSlice(projection["auditTransitionPaths"]), "/accepted") {
		t.Fatalf("first accepted history delivery did not project exact transition facts: %#v", projection)
	}
	if projection["auditPathsOverflow"] != false {
		t.Fatalf("first accepted history delivery unexpectedly overflowed: %#v", projection)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": accepted.SessionID}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
		t.Fatalf("first accepted history delivery did not converge its owned generation: %#v", state)
	}
	if err := mw.recordCwdObservation(ctx, accepted, retention); err != nil {
		t.Fatal(err)
	}
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": accepted.SessionID}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(stringSlice(projection["auditVisitedPaths"]), "/accepted") {
		t.Fatalf("duplicate retry changed exact event projection facts: %#v", projection)
	}
}

func TestFA016PaddedCanonicalBackfillConvergesOnce(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var historyFinds int
	monitor := &event.CommandMonitor{Started: func(_ context.Context, started *event.CommandStartedEvent) {
		if cwdEventHistoryFind(started) {
			historyFinds++
		}
	}}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI).SetMonitor(monitor))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC)
	_, err = db.Collection("cwd_session_state").InsertMany(ctx, []any{
		bson.M{"_id": "source-object-different", "sessionId": "  padded-canonical  ", "cwdState": bson.M{"path": " /home/padded "}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)},
		bson.M{"_id": "legacy-source-different", "session_id": "  padded-legacy  ", "cwdState": bson.M{"path": "/etc/padded"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)},
		bson.M{"_id": "malformed-id", "sessionId": "   ", "cwdState": bson.M{"path": "/etc"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)},
		bson.M{"_id": "malformed-path", "sessionId": "bad-path", "cwdState": bson.M{"path": "relative"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "auditProjectionGeneration": int64(1), "auditProjectionPendingGeneration": int64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection("cwd_events").InsertMany(ctx, []any{
		bson.M{"_id": "padded-canonical-event", "eventId": "padded-canonical-event", "sessionId": "  padded-canonical  ", "action": "changed", "fromPath": "/home/padded", "toPath": "/var/padded", "at": closedAt},
		bson.M{"_id": "padded-legacy-event", "eventId": "padded-legacy-event", "session_id": "  padded-legacy  ", "action": "changed", "fromPath": "/etc/padded", "toPath": "/opt/padded", "at": closedAt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"padded-canonical", "padded-legacy"} {
		doc := bson.M{}
		if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc); err != nil {
			t.Fatalf("canonical projection %s missing: %v", id, err)
		}
		if doc["sessionId"] != id || doc["auditProjectionVersion"] != cwdAuditProjectionVersion || bsonInt64(doc["auditEventCount"]) != 1 {
			t.Fatalf("padded row did not converge to v2 facts: %#v", doc)
		}
	}
	for _, sourceID := range []string{"source-object-different", "legacy-source-different"} {
		doc := bson.M{}
		if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": sourceID}).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["auditProjectionVersion"] != cwdAuditProjectionVersion || bsonInt64(doc["auditProjectionReadyGeneration"]) != bsonInt64(doc["auditProjectionGeneration"]) {
			t.Fatalf("source %s did not receive generation-owned ready marker: %#v", sourceID, doc)
		}
		if _, pending := doc["auditProjectionPendingGeneration"]; pending {
			t.Fatalf("source %s retained pending work after convergence: %#v", sourceID, doc)
		}
	}
	if _, err := db.Collection(cwdAuditProjectionCollection).DeleteOne(ctx, bson.M{"_id": "malformed-id"}); err != nil {
		t.Fatal(err)
	}
	historyFinds = 0
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if historyFinds != 0 {
		t.Fatalf("converged padded rows performed history reads on the next reconciliation pass: %d", historyFinds)
	}
}

func TestFA016EventOutboxSurvivesCloseBeforeHistoryInsert(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 5, 0, 0, 0, time.UTC)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "event-outbox", SourceEventID: "initial", At: base, Path: "/origin", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}

	pendingOwned := make(chan struct{})
	releaseWriter := make(chan struct{})
	var once sync.Once
	mw.auditAfterCwdEventPending = func() {
		once.Do(func() {
			close(pendingOwned)
			<-releaseWriter
		})
	}
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- mw.recordCwdObservation(ctx, cwdObservation{SessionID: "event-outbox", SourceEventID: "transition", At: base.Add(time.Minute), FromPath: "/origin", Path: "/after", Action: "changed", Status: "confirmed"}, retention)
	}()
	<-pendingOwned

	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	ownedGeneration := bsonInt64(state["auditProjectionPendingGeneration"])
	if ownedGeneration == 0 || bsonInt64(state["auditProjectionReadyGeneration"]) == ownedGeneration {
		t.Fatalf("history writer did not own a distinct pending generation: %#v", state)
	}
	if count, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:transition"}); err != nil || count != 0 {
		t.Fatalf("history event committed before the ownership barrier count=%d err=%v", count, err)
	}

	// The close writer advances and converges its newer generation while the
	// original history writer is still paused before cwd_events upsert.
	if err := mw.closeCwdSession(ctx, "event-outbox", base.Add(2*time.Minute), retention); err != nil {
		t.Fatal(err)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending {
		t.Fatalf("close did not converge its owned generation: %#v", state)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 0 {
		t.Fatalf("close projected an event that had not committed yet: %#v", projection)
	}

	close(releaseWriter)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdEventPending = nil
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	paths := stringSlice(projection["auditTransitionPaths"])
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(paths, "/origin") || !containsString(paths, "/after") || projection["auditPathsOverflow"] != false {
		t.Fatalf("late event did not converge exact closed projection facts: %#v", projection)
	}
	if lifecycle, _ := projection["lifecycle"].(bson.M); lifecycle["status"] != "closed" {
		t.Fatalf("late event revived the closed projection: %#v", projection)
	}
	if pending, _ := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:transition", "auditProjectionPending": true}); pending != 0 {
		t.Fatalf("durable event outbox marker was not cleared after convergence: %d", pending)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
		t.Fatalf("late event left source generation markers dirty: %#v", state)
	}

	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "event-outbox"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 {
		t.Fatalf("reconciliation was not exactly once after convergence: %#v", projection)
	}
}

func TestFA016PendingEventFailureRetryAndCrashRecovery(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "retry-session", SourceEventID: "retry-initial", At: base, Path: "/origin", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("injected event upsert failure")
	mw.auditBeforeCwdEventUpsert = func() error { return failed }
	transition := cwdObservation{SessionID: "retry-session", SourceEventID: "retry-transition", At: base.Add(time.Minute), FromPath: "/origin", Path: "/after", Action: "changed", Status: "confirmed"}
	if err := mw.recordCwdObservation(ctx, transition, retention); !errors.Is(err, failed) {
		t.Fatalf("expected deterministic pre-upsert failure, got %v", err)
	}
	mw.auditBeforeCwdEventUpsert = nil
	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "retry-session"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, exists := state["auditProjectionPendingEventCount"]; exists {
		t.Fatalf("retired source counter was recreated after failed reservation: %#v", state)
	}
	if count, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:retry-transition"}); err != nil || count != 0 {
		t.Fatalf("failed event upsert became durable unexpectedly count=%d err=%v", count, err)
	}

	if err := mw.closeCwdSession(ctx, "retry-session", base.Add(2*time.Minute), retention); err != nil {
		t.Fatal(err)
	}
	if err := mw.recordCwdObservation(ctx, transition, retention); err != nil {
		t.Fatal(err)
	}
	if pending, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:retry-transition", "auditProjectionPending": true}); err != nil || pending != 0 {
		t.Fatalf("successful retry did not converge its event marker pending=%d err=%v", pending, err)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "retry-session"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(stringSlice(projection["auditTransitionPaths"]), "/origin") || !containsString(stringSlice(projection["auditTransitionPaths"]), "/after") {
		t.Fatalf("retry did not rebuild exact projection facts: %#v", projection)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "retry-session"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, exists := state["auditProjectionPendingEventCount"]; exists || state["auditProjectionReadyGeneration"] != state["auditProjectionGeneration"] {
		t.Fatalf("retry left source ownership dirty: %#v", state)
	}
	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}

	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "crash-session", SourceEventID: "crash-initial", At: base, Path: "/origin", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	if err := mw.closeCwdSession(ctx, "crash-session", base.Add(2*time.Minute), retention); err != nil {
		t.Fatal(err)
	}
	durable := make(chan struct{})
	release := make(chan struct{})
	mw.auditAfterCwdEventWrite = func() {
		close(durable)
		<-release
	}
	crashCtx, crashCancel := context.WithCancel(context.Background())
	crashed := make(chan error, 1)
	go func() {
		crashed <- mw.recordCwdObservation(crashCtx, cwdObservation{SessionID: "crash-session", SourceEventID: "crash-transition", At: base.Add(3 * time.Minute), FromPath: "/origin", Path: "/crash-after-insert", Action: "changed", Status: "confirmed"}, retention)
	}()
	<-durable
	if pending, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:crash-transition", "auditProjectionPending": true}); err != nil || pending != 1 {
		t.Fatalf("crash barrier did not leave a durable pending event pending=%d err=%v", pending, err)
	}
	crashCancel()
	close(release)
	if err := <-crashed; err == nil {
		t.Fatal("crashed writer unexpectedly projected after its context was cancelled")
	}
	mw.auditAfterCwdEventWrite = nil
	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}
	if pending, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"_id": "cwd:crash-transition", "auditProjectionPending": true}); err != nil || pending != 0 {
		t.Fatalf("reconciliation did not clear crash-recovered event pending=%d err=%v", pending, err)
	}
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "crash-session"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(projection["auditEventCount"]) != 1 || !containsString(stringSlice(projection["auditTransitionPaths"]), "/crash-after-insert") {
		t.Fatalf("crash recovery did not rebuild exact facts: %#v", projection)
	}
}

func TestFA016ConcurrentReconcilersOwnPendingMarkersExactlyOnce(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mwA := &MongoWriter{enabled: true, db: db}
	mwB := &MongoWriter{enabled: true, db: db}
	if err := mwA.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	if err := mwA.recordCwdObservation(ctx, cwdObservation{SessionID: "marker-race", SourceEventID: "marker-initial", At: base, Path: "/origin", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	if err := mwA.closeCwdSession(ctx, "marker-race", base.Add(time.Minute), retention); err != nil {
		t.Fatal(err)
	}

	makeDurablePending := func(mw *MongoWriter, writerContext context.Context, eventID, path string) (<-chan struct{}, func() error) {
		durable := make(chan struct{})
		release := make(chan struct{})
		mw.auditAfterCwdEventWrite = func() {
			close(durable)
			<-release
		}
		done := make(chan error, 1)
		go func() {
			done <- mw.recordCwdObservation(writerContext, cwdObservation{SessionID: "marker-race", SourceEventID: eventID, At: base.Add(2 * time.Minute), FromPath: "/origin", Path: path, Action: "changed", Status: "confirmed"}, retention)
		}()
		return durable, func() error {
			close(release)
			err := <-done
			mw.auditAfterCwdEventWrite = nil
			return err
		}
	}
	writerCtxA, cancelA := context.WithCancel(context.Background())
	writerCtxB, cancelB := context.WithCancel(context.Background())
	durableA, finishA := makeDurablePending(mwA, writerCtxA, "marker-a", "/a")
	<-durableA
	durableB, finishB := makeDurablePending(mwB, writerCtxB, "marker-b", "/b")
	<-durableB
	cancelA()
	cancelB()
	if err := finishA(); err == nil {
		t.Fatal("writer A unexpectedly projected after cancellation")
	}
	if err := finishB(); err == nil {
		t.Fatal("writer B unexpectedly projected after cancellation")
	}
	if pending, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"auditProjectionPending": true}); err != nil || pending != 2 {
		t.Fatalf("expected two durable pending events pending=%d err=%v", pending, err)
	}

	firstRead := make(chan struct{})
	releaseFirst := make(chan struct{})
	var readOnce sync.Once
	mwA.auditBackfillAfterHistoryRead = func() {
		readOnce.Do(func() {
			close(firstRead)
			<-releaseFirst
		})
	}
	reconciledA := make(chan error, 1)
	reconciledB := make(chan error, 1)
	go func() { reconciledA <- mwA.backfillCwdAuditProjection(ctx, retention) }()
	<-firstRead
	go func() { reconciledB <- mwB.backfillCwdAuditProjection(ctx, retention) }()
	if err := <-reconciledB; err != nil {
		t.Fatal(err)
	}
	close(releaseFirst)
	if err := <-reconciledA; err != nil {
		t.Fatal(err)
	}
	mwA.auditBackfillAfterHistoryRead = nil

	if pending, err := db.Collection("cwd_events").CountDocuments(ctx, bson.M{"auditProjectionPending": true}); err != nil || pending != 0 {
		t.Fatalf("concurrent reconcilers did not converge both markers pending=%d err=%v", pending, err)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "marker-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	paths := stringSlice(projection["auditTransitionPaths"])
	if bsonInt64(projection["auditEventCount"]) != 2 || !containsString(paths, "/a") || !containsString(paths, "/b") {
		t.Fatalf("concurrent reconcilers lost exact event facts: %#v", projection)
	}
	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "marker-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, exists := state["auditProjectionPendingEventCount"]; exists || state["auditProjectionReadyGeneration"] != state["auditProjectionGeneration"] {
		t.Fatalf("concurrent reconciliation left retired/dirty source ownership: %#v", state)
	}

	if _, err := db.Collection("cwd_events").InsertOne(ctx, bson.M{"_id": "ownership-only", "eventId": "ownership-only", "sessionId": "marker-race", "auditProjectionPending": true}); err != nil {
		t.Fatal(err)
	}
	ownedResults := make(chan bool, 2)
	errorResults := make(chan error, 2)
	go func() {
		owned, clearErr := mwA.clearCwdEventProjectionWork(ctx, "ownership-only")
		ownedResults <- owned
		errorResults <- clearErr
	}()
	go func() {
		owned, clearErr := mwB.clearCwdEventProjectionWork(ctx, "ownership-only")
		ownedResults <- owned
		errorResults <- clearErr
	}()
	ownedCount := 0
	for range 2 {
		if <-ownedResults {
			ownedCount++
		}
		if clearErr := <-errorResults; clearErr != nil {
			t.Fatal(clearErr)
		}
	}
	if ownedCount != 1 {
		t.Fatalf("marker ownership CAS was not exclusive: %d owners", ownedCount)
	}
}

func TestFA016RejectedObservedCannotStealGenerationOwnership(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	base := time.Date(2026, 9, 20, 6, 0, 0, 0, time.UTC)
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "ownership-race", SourceEventID: "initial", At: base, Path: "/initial", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}

	newerStateWritten := make(chan struct{})
	releaseNewer := make(chan struct{})
	var newerOnce atomic.Bool
	mw.auditAfterCwdStateUpdate = func() {
		if newerOnce.CompareAndSwap(false, true) {
			close(newerStateWritten)
			<-releaseNewer
		}
	}
	newerDone := make(chan error, 1)
	go func() {
		newerDone <- mw.recordCwdObservation(ctx, cwdObservation{SessionID: "ownership-race", SourceEventID: "newer", At: base.Add(2 * time.Minute), Path: "/newer", Action: "observed", Status: "observed"}, retention)
	}()
	<-newerStateWritten
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "ownership-race", SourceEventID: "older", At: base.Add(time.Minute), Path: "/rejected", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(state["auditProjectionPendingGeneration"]) != 2 || bsonInt64(state["auditProjectionReadyGeneration"]) != 1 {
		t.Fatalf("rejected observed payload changed newer ownership markers: %#v", state)
	}
	projection := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if cwdState, _ := projection["cwdState"].(bson.M); cwdState["path"] != "/initial" {
		t.Fatalf("rejected observed payload seeded stale projection facts: %#v", projection)
	}
	close(releaseNewer)
	if err := <-newerDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdStateUpdate = nil

	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if cwdState, _ := projection["cwdState"].(bson.M); cwdState["path"] != "/newer" {
		t.Fatalf("newer accepted observation did not win after stale rejection: %#v", projection)
	}

	closeStateWritten := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	mw.auditAfterCwdCloseStateUpdate = func() {
		closeOnce.Do(func() {
			close(closeStateWritten)
			<-releaseClose
		})
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- mw.closeCwdSession(ctx, "ownership-race", base.Add(3*time.Minute), retention) }()
	<-closeStateWritten
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(state["auditProjectionPendingGeneration"]) != 3 || bsonInt64(state["auditProjectionReadyGeneration"]) != 2 {
		t.Fatalf("close writer did not own its pending generation: %#v", state)
	}
	if err := mw.recordCwdObservation(ctx, cwdObservation{SessionID: "ownership-race", SourceEventID: "rejected-after-close", At: base.Add(90 * time.Second), Path: "/still-rejected", Action: "observed", Status: "observed"}, retention); err != nil {
		t.Fatal(err)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if bsonInt64(state["auditProjectionPendingGeneration"]) != 3 || bsonInt64(state["auditProjectionReadyGeneration"]) != 2 {
		t.Fatalf("rejected observed payload stole close ownership: %#v", state)
	}

	// Treat the paused close owner as crashed. Reconciliation must repair the
	// authoritative closed state and only then clear generation 3.
	if err := mw.backfillCwdAuditProjection(ctx, retention); err != nil {
		t.Fatal(err)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != 3 {
		t.Fatalf("reconciliation did not repair the abandoned close generation: %#v", state)
	}
	projection = bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": "ownership-race"}).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	if cwdState, _ := projection["cwdState"].(bson.M); cwdState["path"] != "/newer" {
		t.Fatalf("reconciliation used rejected payload instead of authoritative state: %#v", projection)
	}
	if lifecycle, _ := projection["lifecycle"].(bson.M); lifecycle["status"] != "closed" {
		t.Fatalf("reconciliation did not preserve the close boundary: %#v", projection)
	}
	close(releaseClose)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	mw.auditAfterCwdCloseStateUpdate = nil
}

func TestFA016OldWriterCutoverConvergesCanonicalAndLegacyRows(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var historyFinds int32
	monitor := &event.CommandMonitor{Started: func(_ context.Context, started *event.CommandStartedEvent) {
		if cwdEventHistoryFind(started) {
			atomic.AddInt32(&historyFinds, 1)
		}
	}}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI).SetMonitor(monitor))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	if _, err := db.Collection("cwd_audit_projection_meta").InsertOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID, "projectionVersion": cwdAuditProjectionVersion, "backfillCompletedAt": closedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("cwd_session_state").InsertMany(ctx, []any{
		bson.M{"_id": "old-canonical-source", "sessionId": "old-canonical", "sourceIp": "198.51.100.30", "cwdState": bson.M{"path": "/home/old"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour)},
		bson.M{"_id": "old-legacy-source", "session_id": "old-legacy", "sourceIp": "198.51.100.31", "cwdState": bson.M{"path": "/var/old"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("cwd_events").InsertMany(ctx, []any{
		bson.M{"_id": "old-canonical-event", "eventId": "old-canonical-event", "sessionId": "old-canonical", "action": "changed", "fromPath": "/home/old", "toPath": "/etc/old", "at": closedAt},
		bson.M{"_id": "old-legacy-event", "eventId": "old-legacy-event", "session_id": "old-legacy", "action": "changed", "fromPath": "/var/old", "toPath": "/opt/old", "at": closedAt},
	}); err != nil {
		t.Fatal(err)
	}

	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old-canonical", "old-legacy"} {
		doc := bson.M{}
		if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["sessionId"] != id || doc["auditProjectionVersion"] != cwdAuditProjectionVersion || bsonInt64(doc["auditEventCount"]) != 1 {
			t.Fatalf("old writer row %s did not receive exact v2 projection: %#v", id, doc)
		}
		stateID := id + "-source"
		state := bson.M{}
		if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": stateID}).Decode(&state); err != nil {
			t.Fatal(err)
		}
		if state["auditProjectionVersion"] != cwdAuditProjectionVersion || bsonInt64(state["auditProjectionReadyGeneration"]) != bsonInt64(state["auditProjectionGeneration"]) {
			t.Fatalf("old writer row %s did not receive generation-owned readiness: %#v", id, state)
		}
		if _, pending := state["auditProjectionPendingGeneration"]; pending {
			t.Fatalf("old writer row %s retained pending work: %#v", id, state)
		}
	}
	atomic.StoreInt32(&historyFinds, 0)
	if err := mw.backfillCwdAuditProjection(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&historyFinds); got != 0 {
		t.Fatalf("steady-state cutover reconciliation reread cwd_events for converged rows: %d", got)
	}
}

func TestFA016SourceOwnedRetentionRepairsProjectionFirstDeletion(t *testing.T) {
	target, skip := fa016IntegrationTarget(t)
	if skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(target.URI))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(target.Database)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	retention := time.Hour
	closedAt := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	expiresAt := closedAt.Add(retention)
	const sessionID = "retention-ordering-race"
	if _, err := db.Collection("cwd_audit_projection_meta").InsertOne(ctx, bson.M{"_id": cwdAuditProjectionMetaID, "projectionVersion": cwdAuditProjectionVersion}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("cwd_session_state").InsertOne(ctx, bson.M{
		"_id": sessionID, "sessionId": sessionID, "sourceIp": "198.51.100.77",
		"cwdState":      bson.M{"path": "/current", "status": "confirmed", "observedAt": closedAt, "sourceEventId": "state-current"},
		"stateSequence": closedAt.UnixNano(), "stateSourceEventId": "state-current",
		"lifecycle":              bson.M{"status": "closed", "startedAt": closedAt.Add(-time.Minute), "closedAt": closedAt},
		"auditProjectionVersion": cwdAuditProjectionVersion, "auditProjectionGeneration": int64(7), "auditProjectionReadyGeneration": int64(7),
		"expires_at": expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("cwd_events").InsertMany(ctx, []any{
		bson.M{"_id": "retention-ordering-entered", "eventId": "retention-ordering-entered", "sessionId": sessionID, "action": "entered", "fromPath": "/", "toPath": "/home/cowrie", "at": closedAt.Add(-2 * time.Minute), "expires_at": expiresAt},
		bson.M{"_id": "retention-ordering-changed", "eventId": "retention-ordering-changed", "sessionId": sessionID, "action": "changed", "fromPath": "/home/cowrie", "toPath": "/etc", "at": closedAt.Add(-time.Minute), "expires_at": expiresAt},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(cwdAuditProjectionCollection).InsertOne(ctx, bson.M{
		"_id": sessionID, "sessionId": sessionID, "sourceIp": "198.51.100.77",
		"cwdState": bson.M{"path": "/current", "status": "confirmed"}, "lifecycle": bson.M{"status": "closed", "startedAt": closedAt.Add(-time.Minute), "closedAt": closedAt},
		"auditTransitionPaths": bson.A{"/home/cowrie", "/etc"}, "auditVisitedPaths": bson.A{"/current", "/home/cowrie", "/etc"}, "auditHomeOnly": false, "auditEventCount": int64(2), "auditHistoryRevision": int64(2),
		"auditProjectionVersion": cwdAuditProjectionVersion, "auditProjectionGeneration": int64(7), "expires_at": expiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate projection-first deletion while deliberately preserving the
	// ready source row. The production repair path, not a close retry, must
	// rebuild this session.
	if _, err := db.Collection(cwdAuditProjectionCollection).DeleteOne(ctx, bson.M{"_id": sessionID}); err != nil {
		t.Fatal(err)
	}
	state := bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": sessionID}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != 7 {
		t.Fatalf("fixture did not preserve the ready/no-pending source state: %#v", state)
	}

	results := make(chan error, 2)
	go func() { results <- mw.backfillCwdAuditProjection(ctx, retention) }()
	go func() { results <- mw.backfillCwdAuditProjection(ctx, retention) }()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	repaired := bson.M{}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": sessionID}).Decode(&repaired); err != nil {
		t.Fatalf("production reconciliation did not reconstruct the projection: %v", err)
	}
	if repaired["sessionId"] != sessionID || repaired["auditProjectionVersion"] != cwdAuditProjectionVersion || bsonInt64(repaired["auditEventCount"]) != 2 || !testBSONTime(repaired["expires_at"]).Equal(expiresAt) {
		t.Fatalf("reconstructed projection facts are not exact: %#v", repaired)
	}
	if got := stringSlice(repaired["auditTransitionPaths"]); !containsString(got, "/home/cowrie") || !containsString(got, "/etc") {
		t.Fatalf("reconstructed transition paths are incomplete: %#v", repaired)
	}
	if got := stringSlice(repaired["auditVisitedPaths"]); !containsString(got, "/current") || !containsString(got, "/home/cowrie") || !containsString(got, "/etc") {
		t.Fatalf("reconstructed visited paths are incomplete: %#v", repaired)
	}
	state = bson.M{}
	if err := db.Collection("cwd_session_state").FindOne(ctx, bson.M{"_id": sessionID}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if _, pending := state["auditProjectionPendingGeneration"]; pending || bsonInt64(state["auditProjectionReadyGeneration"]) != 7 {
		t.Fatalf("reconciliation did not republish the exact ready marker: %#v", state)
	}

	// Explain evidence for both new bounded probes. The source repair query is
	// limited to one batch and the cleanup query is limited to one batch.
	for name, spec := range map[string]struct {
		collection string
		filter     bson.M
		sort       bson.D
	}{
		"repair":  {"cwd_session_state", missingCwdAuditProjectionQuery("sessionId", ""), bson.D{{Key: "sessionId", Value: 1}}},
		"cleanup": {cwdAuditProjectionCollection, cwdAuditProjectionCleanupQuery(time.Now().UTC()), bson.D{{Key: "expires_at", Value: 1}}},
	} {
		var explained bson.M
		if err := db.RunCommand(ctx, bson.D{{Key: "explain", Value: bson.D{{Key: "find", Value: spec.collection}, {Key: "filter", Value: spec.filter}, {Key: "sort", Value: spec.sort}, {Key: "limit", Value: int64(cwdAuditProjectionRepairBatchSize)}}}, {Key: "verbosity", Value: "executionStats"}}).Decode(&explained); err != nil {
			t.Fatalf("explain %s: %v", name, err)
		}
		planText := fmt.Sprint(explained)
		if strings.Contains(planText, "COLLSCAN") || !strings.Contains(planText, "IXSCAN") {
			t.Fatalf("explain %s used COLLSCAN: %#v", name, explained)
		}
		if examined := maxExplainMetric(explained, "totalDocsExamined"); examined > int64(cwdAuditProjectionRepairBatchSize) {
			t.Fatalf("explain %s exceeded the %d-document repair/cleanup bound: %d", name, cwdAuditProjectionRepairBatchSize, examined)
		}
	}

	// Source-owned cleanup removes an expired orphan only after its source is
	// gone; it never deletes a projection while the source is retained.
	orphanID := "retention-ordering-orphan"
	if _, err := db.Collection(cwdAuditProjectionCollection).InsertOne(ctx, bson.M{"_id": orphanID, "sessionId": orphanID, "expires_at": time.Now().UTC().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	deleted, err := mw.cleanupOrphanedCwdAuditProjections(ctx, time.Now().UTC())
	if err != nil || deleted != 1 {
		t.Fatalf("orphan cleanup did not delete exactly one source-less projection: deleted=%d err=%v", deleted, err)
	}
	if err := db.Collection(cwdAuditProjectionCollection).FindOne(ctx, bson.M{"_id": sessionID}).Err(); err != nil {
		t.Fatalf("retained source projection was cleaned up: %v", err)
	}
}

func fa016IntegrationTarget(t *testing.T) (fa016MongoTarget, bool) {
	uri := os.Getenv("FA016_MONGO_URI")
	databaseName := os.Getenv("FA016_MONGO_DB")
	runID := os.Getenv("FA016_MONGO_RUN_ID")
	if uri == "" && databaseName == "" && runID == "" {
		t.Skip("FA016_MONGO_URI is not set")
		return fa016MongoTarget{}, true
	}
	target, err := validateFA016MongoTarget(uri, databaseName, runID)
	if err != nil {
		t.Fatal(err)
	}
	return target, false
}

func cwdEventHistoryFind(started *event.CommandStartedEvent) bool {
	if started.CommandName != "find" || started.Command.Lookup("find").StringValue() != "cwd_events" {
		return false
	}
	// The pending-marker cursor and final existence probe are bounded outbox
	// probes, not authoritative history reads. Only count session/action
	// history filters for the steady-state assertions.
	return !strings.Contains(started.Command.Lookup("filter").String(), "auditProjectionPending")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func maxExplainMetric(value any, key string) int64 {
	var max int64
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case bson.M:
			if raw, ok := typed[key]; ok {
				switch number := raw.(type) {
				case int32:
					if int64(number) > max {
						max = int64(number)
					}
				case int64:
					if number > max {
						max = number
					}
				case int:
					if int64(number) > max {
						max = int64(number)
					}
				case float64:
					if int64(number) > max {
						max = int64(number)
					}
				}
			}
			for _, item := range typed {
				visit(item)
			}
		case bson.A:
			for _, item := range typed {
				visit(item)
			}
		case []any:
			for _, item := range typed {
				visit(item)
			}
		}
	}
	visit(value)
	return max
}

func stringSlice(value any) []string {
	result := []string{}
	switch values := value.(type) {
	case bson.A:
		for _, raw := range values {
			if item, ok := raw.(string); ok {
				result = append(result, item)
			}
		}
	case []any:
		for _, raw := range values {
			if item, ok := raw.(string); ok {
				result = append(result, item)
			}
		}
	}
	return result
}

func testBSONTime(value any) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case primitive.DateTime:
		return typed.Time()
	default:
		return time.Time{}
	}
}
