package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const manifestCollection = "hardware_backup_manifests"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		return fmt.Errorf("connect MongoDB: %w", err)
	}
	defer mongoClient.Disconnect(ctx)

	pingCtx, cancelPing := context.WithTimeout(ctx, 30*time.Second)
	defer cancelPing()
	if err := mongoClient.Ping(pingCtx, nil); err != nil {
		return fmt.Errorf("ping MongoDB: %w", err)
	}

	database := mongoClient.Database(cfg.MongoDatabase)
	manifests := database.Collection(manifestCollection)
	snapshots := database.Collection(storageSnapshotCollection)
	if cfg.Mode == "control" {
		return runControlLoop(ctx, mongoClient, cfg, database, manifests, snapshots)
	}
	return runScheduledBackup(ctx, cfg, database, manifests, snapshots)
}

func runScheduledBackup(
	ctx context.Context,
	cfg Config,
	database *mongo.Database,
	manifests *mongo.Collection,
	snapshots *mongo.Collection,
) error {
	b2Ctx, cancelB2 := context.WithTimeout(ctx, 2*time.Minute)
	b2, err := NewB2Client(b2Ctx, cfg)
	cancelB2()
	if err != nil {
		return err
	}

	if err := publishConfiguredTargetStatuses(ctx, database, cfg, ""); err != nil {
		log.Printf("backup target status failed: %v", err)
	}
	for _, target := range cfg.Targets {
		days := backupWindow(cfg, time.Now().UTC())
		oldestDay := days[0]
		latestDay := days[len(days)-1]
		log.Printf(
			"backup started target=%s collections=%v bucket=%s days=%s..%s force=%t",
			target.ID,
			backupTargetCollectionNames(target),
			cfg.B2Bucket,
			oldestDay.Format("2006-01-02"),
			latestDay.Format("2006-01-02"),
			cfg.Force,
		)

		err = withBackupLock(ctx, cfg, func() error {
			return runBackupDays(ctx, database, manifests, b2, cfg, target, days, nil)
		})
		if err != nil {
			return fmt.Errorf("backup target %s: %w", target.ID, err)
		}
		log.Printf("backup completed target=%s", target.ID)
	}
	if err := refreshStorageSnapshots(ctx, snapshots, cfg, b2); err != nil {
		log.Printf("B2 storage snapshot failed: %v", err)
	} else {
		log.Printf("B2 storage snapshot updated bucket=%s", cfg.B2Bucket)
	}
	log.Printf("backup run completed targets=%v", backupTargetIDs(cfg.Targets))
	return nil
}

type backupRunProgress struct {
	TotalDays      int
	CompletedDays  int
	SuccessfulDays int
	FailedDays     int
	CurrentDay     string
}

func runBackupDays(
	ctx context.Context,
	database *mongo.Database,
	manifests *mongo.Collection,
	b2 *B2Client,
	cfg Config,
	target BackupTarget,
	days []time.Time,
	onProgress func(backupRunProgress) error,
) error {
	progress := backupRunProgress{TotalDays: len(days)}
	if onProgress != nil {
		if err := onProgress(progress); err != nil {
			return fmt.Errorf("write initial backup progress: %w", err)
		}
	}

	var failures []error
	for index, day := range days {
		progress.CurrentDay = day.Format("2006-01-02")
		if onProgress != nil {
			if err := onProgress(progress); err != nil {
				return fmt.Errorf("write backup progress for %s: %w", progress.CurrentDay, err)
			}
		}

		err := backupDay(ctx, database, manifests, b2, cfg, target, day)
		progress.CompletedDays = index + 1
		if err != nil {
			progress.FailedDays++
			failures = append(failures, err)
			log.Printf("backup failed target=%s day=%s err=%v", target.ID, day.Format("2006-01-02"), err)
		} else {
			progress.SuccessfulDays++
		}
		if onProgress != nil {
			if err := onProgress(progress); err != nil {
				return fmt.Errorf("write backup progress for %s: %w", progress.CurrentDay, err)
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("backup target %s completed with %d failed day(s): %v", target.ID, len(failures), failures[0])
	}
	return nil
}

func backupDay(
	ctx context.Context,
	database *mongo.Database,
	manifests *mongo.Collection,
	b2 *B2Client,
	cfg Config,
	target BackupTarget,
	dayStart time.Time,
) error {
	dayStart = dayStart.UTC().Truncate(24 * time.Hour)
	dayEnd := dayStart.Add(24 * time.Hour)
	manifestID := fmt.Sprintf("%s:%s", target.ID, dayStart.Format("2006-01-02"))

	if !cfg.Force {
		var existing bson.M
		err := manifests.FindOne(ctx, bson.M{"_id": manifestID}, options.FindOne().SetProjection(bson.M{"status": 1})).Decode(&existing)
		if err == nil && existing["status"] == "success" {
			return nil
		}
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("read backup manifest %s: %w", manifestID, err)
		}
	}

	startedAt := time.Now().UTC()
	if err := updateManifest(ctx, manifests, manifestID, bson.M{
		"schema_version": archiveSchemaVersion,
		"target_id":      target.ID,
		"collection":     target.ID,
		"collections":    backupTargetCollectionNames(target),
		"day_start":      dayStart,
		"day_end":        dayEnd,
		"status":         "running",
		"started_at":     startedAt,
		"error":          nil,
	}); err != nil {
		return fmt.Errorf("mark backup %s running: %w", manifestID, err)
	}

	operationCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	archive, err := writeTargetDayArchive(operationCtx, database, cfg, target, dayStart)
	cancel()
	if err != nil {
		_ = markManifestFailed(ctx, manifests, manifestID, err)
		return err
	}
	defer os.Remove(archive.Path)

	if archive.DocumentCount == 0 {
		if err := updateManifest(ctx, manifests, manifestID, bson.M{
			"status":         "success",
			"document_count": int64(0),
			"archive_bytes":  int64(0),
			"object_name":    nil,
			"completed_at":   time.Now().UTC(),
			"error":          nil,
		}); err != nil {
			return fmt.Errorf("mark empty backup %s complete: %w", manifestID, err)
		}
		log.Printf("backup target=%s day=%s has no documents", target.ID, dayStart.Format("2006-01-02"))
		return nil
	}

	objectName := archiveObjectNameForTarget(target, dayStart)
	operationCtx, cancel = context.WithTimeout(ctx, 20*time.Minute)
	uploaded, err := b2.Upload(operationCtx, archive.Path, objectName, "application/gzip", archive.SHA1, archive.SizeBytes)
	cancel()
	if err != nil {
		_ = markManifestFailed(ctx, manifests, manifestID, err)
		return err
	}
	if err := updateManifest(ctx, manifests, manifestID, bson.M{
		"status":         "success",
		"document_count": archive.DocumentCount,
		"archive_bytes":  archive.SizeBytes,
		"archive_sha256": archive.SHA256,
		"object_name":    uploaded.FileName,
		"object_sha1":    uploaded.ContentSha1,
		"completed_at":   time.Now().UTC(),
		"error":          nil,
	}); err != nil {
		return fmt.Errorf("mark backup %s complete: %w", manifestID, err)
	}
	log.Printf(
		"backup target=%s day=%s documents=%d bytes=%d object=%s",
		target.ID,
		dayStart.Format("2006-01-02"),
		archive.DocumentCount,
		archive.SizeBytes,
		uploaded.FileName,
	)
	return nil
}

func updateManifest(ctx context.Context, collection *mongo.Collection, id string, fields bson.M) error {
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": fields},
		options.Update().SetUpsert(true),
	)
	return err
}

func markManifestFailed(ctx context.Context, collection *mongo.Collection, id string, cause error) error {
	return updateManifest(ctx, collection, id, bson.M{
		"status":       "failed",
		"error":        cause.Error(),
		"completed_at": time.Now().UTC(),
	})
}
