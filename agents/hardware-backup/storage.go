package main

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	storageSnapshotCollection    = "b2_storage_snapshots"
	storageSnapshotSchemaVersion = "pti.b2_storage_snapshot.v1"
	storageUsageTimeout          = 10 * time.Minute
)

func refreshStorageSnapshot(ctx context.Context, snapshots *mongo.Collection, cfg Config, b2 *B2Client, targetID string) error {
	usageCtx, cancel := context.WithTimeout(ctx, storageUsageTimeout)
	usage, err := b2.StorageUsage(usageCtx)
	cancel()
	if err != nil {
		return err
	}

	checkedAt := time.Now().UTC()
	target, ok := backupTarget(targetID)
	if !ok {
		return fmt.Errorf("unsupported backup target %q", targetID)
	}
	return writeStorageSnapshots(ctx, snapshots, cfg, usage, checkedAt, []BackupTarget{target})
}

func refreshStorageSnapshots(ctx context.Context, snapshots *mongo.Collection, cfg Config, b2 *B2Client) error {
	usageCtx, cancel := context.WithTimeout(ctx, storageUsageTimeout)
	usage, err := b2.StorageUsage(usageCtx)
	cancel()
	if err != nil {
		return err
	}
	return writeStorageSnapshots(ctx, snapshots, cfg, usage, time.Now().UTC(), cfg.Targets)
}

func writeStorageSnapshots(
	ctx context.Context,
	snapshots *mongo.Collection,
	cfg Config,
	usage b2StorageUsage,
	checkedAt time.Time,
	targets []BackupTarget,
) error {
	for _, target := range targets {
		_, err := snapshots.UpdateOne(ctx, bson.M{"_id": target.ID}, bson.M{
			"$set": bson.M{
				"schema_version": storageSnapshotSchemaVersion,
				"source":         target.ID,
				"bucket":         cfg.B2Bucket,
				"storage_bytes":  usage.StorageBytes,
				"file_versions":  usage.FileVersions,
				"checked_at":     checkedAt,
			},
		}, options.Update().SetUpsert(true))
		if err != nil {
			return fmt.Errorf("write B2 storage snapshot for %s: %w", target.ID, err)
		}
	}
	return nil
}
