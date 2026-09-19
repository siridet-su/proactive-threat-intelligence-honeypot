package main

import (
	"context"
	"fmt"
	"os"
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
		if started.CommandName == "find" && started.Command.Lookup("find").StringValue() == "cwd_events" {
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
	// Simulate a rolling deployment that left the right key pattern without a
	// TTL option. The authoritative owner must repair, not silently accept it.
	if _, err := db.Collection(cwdAuditProjectionCollection).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}}); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}

	// Keep the retained fixtures ahead of the wall clock so Mongo's TTL monitor
	// cannot remove them while the integration assertions are running.
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
	foundTTL := false
	for _, index := range indexes {
		if index["name"] == "expires_at_1" && index["expireAfterSeconds"] == int32(0) {
			foundTTL = true
		}
	}
	if !foundTTL {
		t.Fatalf("projection TTL index was not provisioned: %#v", indexes)
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
	if _, err := db.Collection("cwd_session_state").InsertOne(ctx, bson.M{"_id": legacyExpiry, "session_id": legacyExpiry, "cwdState": bson.M{"path": "/home/cowrie"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}}); err != nil {
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
	if _, err := db.Collection("cwd_session_state").InsertOne(ctx, bson.M{"_id": boundedSession, "sessionId": boundedSession, "cwdState": bson.M{"path": "/home/current"}, "lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour)}); err != nil {
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
	var barrierOnce sync.Once
	mw.auditBackfillAfterHistoryRead = func() {
		barrierOnce.Do(func() {
			close(readComplete)
			<-resume
		})
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
