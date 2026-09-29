package main

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func TestBucketRolloverKeepsManifestAndSnapshotIdentitiesSeparate(t *testing.T) {
	day := time.Date(2026, 9, 20, 7, 0, 0, 0, time.FixedZone("ICT", 7*60*60))
	oldManifest := backupManifestID("old-bucket", hardwareBackupTargetID, day)
	newManifest := backupManifestID("new-bucket", hardwareBackupTargetID, day)
	if oldManifest == newManifest || oldManifest != "bucket:old-bucket:hardware_metrics_1m:2026-09-20" {
		t.Fatalf("manifest identities are not bucket-scoped: %q, %q", oldManifest, newManifest)
	}
	if storageSnapshotID("old-bucket", hardwareBackupTargetID) == storageSnapshotID("new-bucket", hardwareBackupTargetID) {
		t.Fatal("storage snapshots for separate buckets share an identity")
	}
}

func TestManifestBucketFilterRequiresExplicitLegacyAttribution(t *testing.T) {
	withoutLegacy := manifestTargetBucketFilter(hardwareBackupTargetID, "new-bucket", "")
	withOldLegacy := manifestTargetBucketFilter(hardwareBackupTargetID, "new-bucket", "old-bucket")
	withCurrentLegacy := manifestTargetBucketFilter(hardwareBackupTargetID, "new-bucket", "new-bucket")
	for _, filter := range []bson.M{withoutLegacy, withOldLegacy} {
		bucketChoices := filter["$and"].(bson.A)[1].(bson.M)["$or"].(bson.A)
		if len(bucketChoices) != 1 || bucketChoices[0].(bson.M)["bucket"] != "new-bucket" {
			t.Fatalf("old or unknown bucket can satisfy current bucket filter: %v", filter)
		}
	}
	if choices := withCurrentLegacy["$and"].(bson.A)[1].(bson.M)["$or"].(bson.A); len(choices) != 2 {
		t.Fatalf("explicit current-bucket legacy attribution was ignored: %v", withCurrentLegacy)
	}
}

func TestBackupWindowUsesSafetyDays(t *testing.T) {
	cfg := Config{LookbackDays: 30, SafetyDays: 2}
	days := backupWindow(cfg, time.Date(2026, 9, 23, 12, 0, 0, 0, time.FixedZone("ICT", 7*60*60)))

	if len(days) != 29 {
		t.Fatalf("backupWindow() returned %d days, want 29", len(days))
	}
	if got := days[0].Format("2006-01-02"); got != "2026-08-24" {
		t.Fatalf("first backup day = %s, want 2026-08-24", got)
	}
	if got := days[len(days)-1].Format("2006-01-02"); got != "2026-09-21" {
		t.Fatalf("last backup day = %s, want 2026-09-21", got)
	}
}

func TestProgressPercent(t *testing.T) {
	tests := []struct {
		completed int
		total     int
		want      int
	}{
		{completed: 0, total: 0, want: 100},
		{completed: 0, total: 29, want: 0},
		{completed: 14, total: 29, want: 48},
		{completed: 29, total: 29, want: 100},
	}

	for _, test := range tests {
		if got := progressPercent(test.completed, test.total); got != test.want {
			t.Errorf("progressPercent(%d, %d) = %d, want %d", test.completed, test.total, got, test.want)
		}
	}
}
