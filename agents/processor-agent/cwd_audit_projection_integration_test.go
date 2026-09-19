package main

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestFA016AuditProjectionIntegration(t *testing.T) {
	uri := os.Getenv("FA016_MONGO_URI")
	databaseName := os.Getenv("FA016_MONGO_DB")
	if uri == "" {
		t.Skip("FA016_MONGO_URI is not set")
	}
	if databaseName == "" || databaseName == "honeypot_db" || !strings.HasPrefix(databaseName, "pti_fa016_test_") {
		t.Fatalf("refusing FA-016 integration database %q", databaseName)
	}
	parsed, err := url.Parse(uri)
	if err != nil || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") {
		t.Fatalf("refusing non-loopback FA-016 URI %q", uri)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(databaseName)
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	mw := &MongoWriter{enabled: true, db: db}
	if err := mw.ensureIndexes(ctx); err != nil {
		t.Fatal(err)
	}

	closedAt := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	_, err = db.Collection("cwd_session_state").InsertMany(ctx, []any{
		bson.M{
			"_id": "canonical-session", "sessionId": "canonical-session", "sourceIp": "198.51.100.10",
			"cwdState":  bson.M{"path": "/home/cowrie", "status": "confirmed"},
			"lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour),
		},
		bson.M{
			"_id": "legacy-state-id", "session_id": "legacy-session", "sourceIp": "198.51.100.11",
			"cwdState":  bson.M{"path": "/var/tmp", "status": "observed"},
			"lifecycle": bson.M{"status": "closed", "closedAt": closedAt}, "expires_at": closedAt.Add(time.Hour),
		},
	})
	if err != nil {
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
	if err := mw.recordCwdObservation(ctx, lateObservation, time.Hour); err != nil {
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
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
