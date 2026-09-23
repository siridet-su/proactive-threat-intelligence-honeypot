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
	collection := database.Collection(cfg.Collection)
	manifests := database.Collection(manifestCollection)
	if cfg.Mode == "control" {
		return runControlLoop(ctx, mongoClient, cfg, collection, manifests)
	}
	return runScheduledBackup(ctx, cfg, collection, manifests)
}

func runScheduledBackup(
	ctx context.Context,
	cfg Config,
	collection *mongo.Collection,
	manifests *mongo.Collection,
) error {
	b2Ctx, cancelB2 := context.WithTimeout(ctx, 2*time.Minute)
	b2, err := NewB2Client(b2Ctx, cfg)
	cancelB2()
	if err != nil {
		return err
	}

	days := backupWindow(cfg, time.Now().UTC())
	oldestDay := days[0]
	latestDay := days[len(days)-1]
	log.Printf(
		"hardware backup started collection=%s bucket=%s days=%s..%s force=%t",
		cfg.Collection,
		cfg.B2Bucket,
		oldestDay.Format("2006-01-02"),
		latestDay.Format("2006-01-02"),
		cfg.Force,
	)

	err = withBackupLock(ctx, cfg, func() error {
		return runBackupDays(ctx, collection, manifests, b2, cfg, days, nil)
	})
	if err != nil {
		return err
	}
	log.Printf("hardware backup completed")
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
	collection *mongo.Collection,
	manifests *mongo.Collection,
	b2 *B2Client,
	cfg Config,
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

		err := backupDay(ctx, collection, manifests, b2, cfg, day)
		progress.CompletedDays = index + 1
		if err != nil {
			progress.FailedDays++
			failures = append(failures, err)
			log.Printf("hardware backup failed day=%s err=%v", day.Format("2006-01-02"), err)
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
		return fmt.Errorf("hardware backup completed with %d failed day(s): %v", len(failures), failures[0])
	}
	return nil
}

func backupDay(
	ctx context.Context,
	collection *mongo.Collection,
	manifests *mongo.Collection,
	b2 *B2Client,
	cfg Config,
	dayStart time.Time,
) error {
	dayStart = dayStart.UTC().Truncate(24 * time.Hour)
	dayEnd := dayStart.Add(24 * time.Hour)
	manifestID := fmt.Sprintf("%s:%s", cfg.Collection, dayStart.Format("2006-01-02"))

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
		"collection":     cfg.Collection,
		"day_start":      dayStart,
		"day_end":        dayEnd,
		"status":         "running",
		"started_at":     startedAt,
		"error":          nil,
	}); err != nil {
		return fmt.Errorf("mark backup %s running: %w", manifestID, err)
	}

	operationCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	archive, err := writeDayArchive(operationCtx, collection, cfg, dayStart)
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
		log.Printf("hardware backup day=%s has no documents", dayStart.Format("2006-01-02"))
		return nil
	}

	objectName := archiveObjectName(dayStart)
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
		"hardware backup day=%s documents=%d bytes=%d object=%s",
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
