package main

import (
	"fmt"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	hardwareBackupTargetID  = "hardware_metrics_1m"
	threatEventsTargetID    = "threat_events"
	filesystemAuditTargetID = "filesystem_audit"
)

// ArchiveSource describes one MongoDB source that belongs to a logical backup
// target. TimeFields are tried as an OR query so old CWD documents that used
// timestamp remain archivable without making the derived projection a source.
type ArchiveSource struct {
	Collection string
	TimeFields []string
	SortField  string
}

type BackupTarget struct {
	ID        string
	Prefix    string
	Sources   []ArchiveSource
	Sensitive bool
}

var backupTargetCatalog = map[string]BackupTarget{
	hardwareBackupTargetID: {
		ID:     hardwareBackupTargetID,
		Prefix: "hardware_metrics_1m",
		Sources: []ArchiveSource{{
			Collection: "hardware_metrics_1m",
			TimeFields: []string{"timestamp"},
			SortField:  "timestamp",
		}},
	},
	threatEventsTargetID: {
		ID:        threatEventsTargetID,
		Prefix:    "threat_events",
		Sensitive: true,
		Sources: []ArchiveSource{{
			Collection: "events",
			TimeFields: []string{"timestamp"},
			SortField:  "timestamp",
		}},
	},
	filesystemAuditTargetID: {
		ID:     filesystemAuditTargetID,
		Prefix: "filesystem_audit",
		Sources: []ArchiveSource{
			{
				Collection: "cwd_events",
				TimeFields: []string{"at", "timestamp"},
				SortField:  "at",
			},
			{
				Collection: "cwd_session_state",
				TimeFields: []string{"updatedAt", "updated_at", "lifecycle.closedAt", "lifecycle.startedAt"},
				SortField:  "updatedAt",
			},
		},
	},
}

func backupTarget(id string) (BackupTarget, bool) {
	target, ok := backupTargetCatalog[strings.TrimSpace(id)]
	return target, ok
}

func backupTargetForRequest(source string) (BackupTarget, bool) {
	if target, ok := backupTarget(source); ok {
		return target, true
	}
	for _, target := range backupTargetCatalog {
		for _, archiveSource := range target.Sources {
			if archiveSource.Collection == strings.TrimSpace(source) {
				return target, true
			}
		}
	}
	return BackupTarget{}, false
}

func backupTargetRequestSources(targets []BackupTarget) []string {
	seen := make(map[string]struct{})
	sources := make([]string, 0, len(targets))
	for _, target := range targets {
		for _, source := range append([]string{target.ID}, backupTargetCollectionNames(target)...) {
			if _, ok := seen[source]; ok {
				continue
			}
			seen[source] = struct{}{}
			sources = append(sources, source)
		}
	}
	return sources
}

func backupTargetIDs(targets []BackupTarget) []string {
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.ID)
	}
	return ids
}

func targetEnabled(targets []BackupTarget, id string) bool {
	for _, target := range targets {
		if target.ID == id {
			return true
		}
	}
	return false
}

func manifestTargetFilter(targetID string) bson.M {
	return bson.M{"$or": bson.A{
		bson.M{"target_id": targetID},
		bson.M{"collection": targetID},
	}}
}

func backupTargetCollectionNames(target BackupTarget) []string {
	collections := make([]string, 0, len(target.Sources))
	for _, source := range target.Sources {
		collections = append(collections, source.Collection)
	}
	return collections
}

func configuredBackupTargets(raw string, legacyCollection string) ([]BackupTarget, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = strings.TrimSpace(legacyCollection)
	}
	if value == "" {
		value = hardwareBackupTargetID
	}

	seen := make(map[string]struct{})
	targets := make([]BackupTarget, 0)
	for _, item := range strings.Split(value, ",") {
		id := strings.TrimSpace(item)
		if id == "" {
			continue
		}
		// Keep the old BACKUP_COLLECTION=events spelling usable while making
		// the new target name explicit in status and request documents.
		if id == "events" {
			id = threatEventsTargetID
		}
		if id == "cwd_events" || id == "cwd_session_state" {
			id = filesystemAuditTargetID
		}
		if _, ok := seen[id]; ok {
			continue
		}
		target, ok := backupTarget(id)
		if !ok {
			return nil, fmt.Errorf("unsupported backup target %q", id)
		}
		seen[id] = struct{}{}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("BACKUP_TARGETS must contain at least one target")
	}
	return targets, nil
}

func allKnownBackupTargetIDs() []string {
	ids := make([]string, 0, len(backupTargetCatalog))
	for id := range backupTargetCatalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
