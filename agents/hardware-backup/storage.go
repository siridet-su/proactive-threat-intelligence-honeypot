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

func refreshStorageSnapshot(ctx context.Context, snapshots *mongo.Collection, cfg Config, b2 *B2Client) error {
	usageCtx, cancel := context.WithTimeout(ctx, storageUsageTimeout)
	usage, err := b2.StorageUsage(usageCtx)
	cancel()
	if err != nil {
		return err
	}

	checkedAt := time.Now().UTC()
	_, err = snapshots.UpdateOne(ctx, bson.M{"_id": cfg.Collection}, bson.M{
		"$set": bson.M{
			"schema_version": storageSnapshotSchemaVersion,
			"source":         cfg.Collection,
			"bucket":         cfg.B2Bucket,
			"storage_bytes":  usage.StorageBytes,
			"file_versions":  usage.FileVersions,
			"checked_at":     checkedAt,
		},
	}, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("write B2 storage snapshot: %w", err)
	}

	return nil
}
