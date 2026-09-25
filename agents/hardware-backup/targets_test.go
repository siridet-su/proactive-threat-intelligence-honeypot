package main

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func TestConfiguredBackupTargetsMapsLegacyCollections(t *testing.T) {
	targets, err := configuredBackupTargets("events,cwd_events", hardwareBackupTargetID)
	if err != nil {
		t.Fatalf("configuredBackupTargets() error = %v", err)
	}
	if len(targets) != 2 || targets[0].ID != threatEventsTargetID || targets[1].ID != filesystemAuditTargetID {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestFilesystemTargetContainsOnlyAuthoritativeSources(t *testing.T) {
	target, ok := backupTarget(filesystemAuditTargetID)
	if !ok {
		t.Fatal("filesystem target is not registered")
	}
	if len(target.Sources) != 2 {
		t.Fatalf("filesystem sources = %d, want 2", len(target.Sources))
	}
	if target.Sources[0].Collection != "cwd_events" || target.Sources[1].Collection != "cwd_session_state" {
		t.Fatalf("filesystem sources = %#v", target.Sources)
	}
	for _, source := range target.Sources {
		if source.Collection == "cwd_audit_projection" || source.Collection == "cwd_audit_projection_meta" {
			t.Fatalf("derived projection was included: %#v", source)
		}
	}
}

func TestArchiveSourceQueryIncludesLegacyCwdTimestampFields(t *testing.T) {
	target, _ := backupTarget(filesystemAuditTargetID)
	query := archiveSourceQuery(target.Sources[0], time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC))
	conditions, ok := query["$or"].(bson.A)
	if !ok || len(conditions) != 2 {
		t.Fatalf("query = %#v", query)
	}
}

func TestArchiveObjectNameUsesTargetPrefix(t *testing.T) {
	target, _ := backupTarget(filesystemAuditTargetID)
	got := archiveObjectNameForTarget(target, time.Date(2026, 9, 23, 23, 30, 0, 0, time.FixedZone("UTC+7", 7*60*60)))
	want := "filesystem_audit/2026/09/23/archive.jsonl.gz"
	if got != want {
		t.Fatalf("archiveObjectNameForTarget() = %q, want %q", got, want)
	}
}
