package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	targetStatusCollection    = "backup_target_status"
	targetStatusSchemaVersion = "pti.backup_target_status.v1"
)

// publishTargetStatus makes the worker's enabled target set and heartbeat
// observable to the dashboard. A missing row means the Pi has not activated
// that target; it is deliberately different from a manifest row with zero
// records.
func publishTargetStatus(ctx context.Context, database *mongo.Database, cfg Config, target BackupTarget, workerID string) error {
	if workerID == "" {
		hostname, _ := os.Hostname()
		workerID = fmt.Sprintf("%s:%d", hostname, os.Getpid())
	}
	now := time.Now().UTC()
	_, err := database.Collection(targetStatusCollection).UpdateOne(ctx, bson.M{"_id": target.ID}, bson.M{
		"$set": bson.M{
			"schema_version": targetStatusSchemaVersion,
			"target_id":      target.ID,
			"collections":    backupTargetCollectionNames(target),
			"prefix":         target.Prefix,
			"sensitive":      target.Sensitive,
			"enabled":        targetEnabled(cfg.Targets, target.ID),
			"mode":           cfg.Mode,
			"bucket":         cfg.B2Bucket,
			"worker_id":      workerID,
			"poll_seconds":   cfg.ControlPollSeconds,
			"last_seen_at":   now,
			"updated_at":     now,
		},
	}, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("write backup target status %s: %w", target.ID, err)
	}
	return nil
}

func publishConfiguredTargetStatuses(ctx context.Context, database *mongo.Database, cfg Config, workerID string) error {
	for _, targetID := range allKnownBackupTargetIDs() {
		target, ok := backupTarget(targetID)
		if !ok {
			continue
		}
		if err := publishTargetStatus(ctx, database, cfg, target, workerID); err != nil {
			return err
		}
	}
	return nil
}
