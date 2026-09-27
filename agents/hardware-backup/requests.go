package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	requestCollection        = "hardware_backup_requests"
	requestSchemaVersion     = "pti.hardware_backup_request.v1"
	requestActionRunMissing  = "run_missing"
	requestActionRetryFailed = "retry_failed"
	requestStatusPending     = "pending"
	requestStatusRunning     = "running"
	requestStatusSuccess     = "success"
	requestStatusFailed      = "failed"
	requestLeaseDuration     = 30 * time.Minute
)

type backupRequestProgress struct {
	TotalDays      int    `bson:"total_days"`
	CompletedDays  int    `bson:"completed_days"`
	SuccessfulDays int    `bson:"successful_days"`
	FailedDays     int    `bson:"failed_days"`
	CurrentDay     string `bson:"current_day"`
	Percent        int    `bson:"percent"`
}

type backupRequest struct {
	ID            string                `bson:"_id"`
	SchemaVersion string                `bson:"schema_version"`
	Source        string                `bson:"source"`
	Action        string                `bson:"action"`
	RequestedBy   string                `bson:"requested_by"`
	Status        string                `bson:"status"`
	CreatedAt     time.Time             `bson:"created_at"`
	StartedAt     time.Time             `bson:"started_at"`
	CompletedAt   *time.Time            `bson:"completed_at,omitempty"`
	HeartbeatAt   time.Time             `bson:"heartbeat_at"`
	WorkerID      string                `bson:"worker_id"`
	Progress      backupRequestProgress `bson:"progress"`
	Error         string                `bson:"error,omitempty"`
}

func runControlLoop(
	ctx context.Context,
	mongoClient *mongo.Client,
	cfg Config,
	database *mongo.Database,
	manifests *mongo.Collection,
	snapshots *mongo.Collection,
) error {
	requests := mongoClient.Database(cfg.MongoDatabase).Collection(requestCollection)
	hostname, _ := os.Hostname()
	workerID := fmt.Sprintf("%s:%d", hostname, os.Getpid())
	b2Ctx, cancelB2 := context.WithTimeout(ctx, 2*time.Minute)
	_, b2Err := NewB2Client(b2Ctx, cfg)
	cancelB2()
	if b2Err != nil {
		log.Printf("backup target activation check failed: %v", b2Err)
	} else if err := publishConfiguredTargetStatuses(ctx, database, cfg, workerID); err != nil {
		log.Printf("backup target status failed: %v", err)
	}
	log.Printf("backup control loop started worker=%s targets=%v poll_seconds=%d", workerID, backupTargetIDs(cfg.Targets), cfg.ControlPollSeconds)

	poll := time.NewTicker(time.Duration(cfg.ControlPollSeconds) * time.Second)
	defer poll.Stop()
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go func() {
		heartbeat := time.NewTicker(time.Duration(cfg.ControlPollSeconds) * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-heartbeat.C:
				if err := publishConfiguredTargetStatuses(heartbeatCtx, database, cfg, workerID); err != nil {
					log.Printf("backup target heartbeat failed: %v", err)
				}
			}
		}
	}()

	for {
		request, err := claimNextBackupRequest(ctx, requests, backupTargetRequestSources(cfg.Targets), workerID)
		if err != nil {
			log.Printf("backup request claim failed: %v", err)
		} else if request != nil {
			target, ok := backupTargetForRequest(request.Source)
			if !ok || !targetEnabled(cfg.Targets, target.ID) {
				log.Printf("backup request id=%s ignored unsupported or disabled source=%s", request.ID, request.Source)
				_ = markBackupRequestFailed(ctx, requests, request.ID, fmt.Errorf("backup target %q is not enabled", request.Source))
			} else if err := processBackupRequest(ctx, requests, database, manifests, cfg, target, *request, snapshots); err != nil {
				log.Printf("backup request id=%s target=%s failed: %v", request.ID, target.ID, err)
			}
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
		}
	}
}

func claimNextBackupRequest(ctx context.Context, requests *mongo.Collection, sources []string, workerID string) (*backupRequest, error) {
	now := time.Now().UTC()
	staleBefore := now.Add(-requestLeaseDuration)
	filter := bson.M{
		"source":         bson.M{"$in": sources},
		"schema_version": requestSchemaVersion,
		"$or": bson.A{
			bson.M{"status": requestStatusPending},
			bson.M{"status": requestStatusRunning, "heartbeat_at": bson.M{"$lt": staleBefore}},
		},
	}
	update := bson.M{"$set": bson.M{
		"status":       requestStatusRunning,
		"started_at":   now,
		"heartbeat_at": now,
		"worker_id":    workerID,
		"completed_at": nil,
		"error":        nil,
	}}
	var request backupRequest
	err := requests.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().
		SetSort(bson.D{{Key: "created_at", Value: 1}}).
		SetReturnDocument(options.After)).Decode(&request)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim backup request: %w", err)
	}
	return &request, nil
}

func processBackupRequest(
	ctx context.Context,
	requests *mongo.Collection,
	database *mongo.Database,
	manifests *mongo.Collection,
	cfg Config,
	target BackupTarget,
	request backupRequest,
	snapshots *mongo.Collection,
) error {
	days, err := selectBackupRequestDays(ctx, manifests, target, cfg, request.Action)
	if err != nil {
		return markBackupRequestFailed(ctx, requests, request.ID, err)
	}

	progress := backupRequestProgress{TotalDays: len(days), Percent: progressPercent(0, len(days))}
	if err := updateBackupRequestProgress(ctx, requests, request.ID, progress); err != nil {
		return err
	}
	log.Printf("backup request id=%s target=%s action=%s days=%d", request.ID, target.ID, request.Action, len(days))

	if len(days) == 0 {
		return completeBackupRequest(ctx, requests, request.ID, progress, nil)
	}

	b2Ctx, cancelB2 := context.WithTimeout(ctx, 2*time.Minute)
	b2, err := NewB2Client(b2Ctx, cfg)
	cancelB2()
	if err != nil {
		return markBackupRequestFailed(ctx, requests, request.ID, err)
	}

	err = withBackupLock(ctx, cfg, func() error {
		return runBackupDays(ctx, database, manifests, b2, cfg, target, days, func(runProgress backupRunProgress) error {
			progress = backupRequestProgress{
				TotalDays:      runProgress.TotalDays,
				CompletedDays:  runProgress.CompletedDays,
				SuccessfulDays: runProgress.SuccessfulDays,
				FailedDays:     runProgress.FailedDays,
				CurrentDay:     runProgress.CurrentDay,
				Percent:        progressPercent(runProgress.CompletedDays, runProgress.TotalDays),
			}
			return updateBackupRequestProgress(ctx, requests, request.ID, progress)
		})
	})
	if storageErr := refreshStorageSnapshot(ctx, snapshots, cfg, b2, target.ID); storageErr != nil {
		log.Printf("B2 storage snapshot failed for request id=%s: %v", request.ID, storageErr)
	}
	return completeBackupRequest(ctx, requests, request.ID, progress, err)
}

func selectBackupRequestDays(ctx context.Context, manifests *mongo.Collection, target BackupTarget, cfg Config, action string) ([]time.Time, error) {
	if action != requestActionRunMissing && action != requestActionRetryFailed {
		return nil, fmt.Errorf("unsupported backup request action %q", action)
	}
	days := backupWindow(cfg, time.Now().UTC())
	if action == requestActionRunMissing {
		var existing []struct {
			DayStart time.Time `bson:"day_start"`
		}
		query := manifestTargetFilter(target.ID)
		query["day_start"] = bson.M{"$gte": days[0], "$lt": days[len(days)-1].Add(24 * time.Hour)}
		cursor, err := manifests.Find(ctx, query,
			options.Find().SetProjection(bson.M{"day_start": 1}))
		if err != nil {
			return nil, fmt.Errorf("read backup manifests: %w", err)
		}
		if err := cursor.All(ctx, &existing); err != nil {
			return nil, fmt.Errorf("decode backup manifests: %w", err)
		}
		known := make(map[string]struct{}, len(existing))
		for _, document := range existing {
			known[document.DayStart.UTC().Format("2006-01-02")] = struct{}{}
		}
		missing := make([]time.Time, 0, len(days))
		for _, day := range days {
			if _, ok := known[day.Format("2006-01-02")]; !ok {
				missing = append(missing, day)
			}
		}
		return missing, nil
	}

	var failed []struct {
		DayStart time.Time `bson:"day_start"`
	}
	query := manifestTargetFilter(target.ID)
	query["status"] = requestStatusFailed
	query["day_start"] = bson.M{"$gte": days[0], "$lt": days[len(days)-1].Add(24 * time.Hour)}
	cursor, err := manifests.Find(ctx, query,
		options.Find().SetProjection(bson.M{"day_start": 1}).SetSort(bson.D{{Key: "day_start", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("read failed backup manifests: %w", err)
	}
	if err := cursor.All(ctx, &failed); err != nil {
		return nil, fmt.Errorf("decode failed backup manifests: %w", err)
	}
	retry := make([]time.Time, 0, len(failed))
	for _, document := range failed {
		retry = append(retry, document.DayStart.UTC().Truncate(24*time.Hour))
	}
	return retry, nil
}

func backupWindow(cfg Config, now time.Time) []time.Time {
	today := now.UTC().Truncate(24 * time.Hour)
	oldest := today.Add(-time.Duration(cfg.LookbackDays) * 24 * time.Hour)
	latest := today.Add(-time.Duration(cfg.SafetyDays) * 24 * time.Hour)
	days := make([]time.Time, 0, cfg.LookbackDays)
	for day := oldest; !day.After(latest); day = day.Add(24 * time.Hour) {
		days = append(days, day)
	}
	return days
}

func updateBackupRequestProgress(ctx context.Context, requests *mongo.Collection, id string, progress backupRequestProgress) error {
	now := time.Now().UTC()
	_, err := requests.UpdateOne(ctx, bson.M{"_id": id, "status": requestStatusRunning}, bson.M{"$set": bson.M{
		"progress":     progress,
		"heartbeat_at": now,
		"updated_at":   now,
	}})
	return err
}

func completeBackupRequest(ctx context.Context, requests *mongo.Collection, id string, progress backupRequestProgress, cause error) error {
	now := time.Now().UTC()
	status := requestStatusSuccess
	fields := bson.M{
		"status":       status,
		"completed_at": now,
		"heartbeat_at": now,
		"updated_at":   now,
		"progress":     progress,
		"error":        nil,
	}
	if cause != nil {
		status = requestStatusFailed
		fields["status"] = status
		fields["error"] = cause.Error()
	}
	_, err := requests.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set":   fields,
		"$unset": bson.M{"active_key": ""},
	})
	if err != nil {
		return fmt.Errorf("complete backup request %s: %w", id, err)
	}
	return cause
}

func markBackupRequestFailed(ctx context.Context, requests *mongo.Collection, id string, cause error) error {
	now := time.Now().UTC()
	_, err := requests.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{
			"status":       requestStatusFailed,
			"completed_at": now,
			"heartbeat_at": now,
			"updated_at":   now,
			"error":        cause.Error(),
		},
		"$unset": bson.M{"active_key": ""},
	})
	if err != nil {
		return fmt.Errorf("mark backup request %s failed: %w", id, err)
	}
	return cause
}

func progressPercent(completed, total int) int {
	if total <= 0 {
		return 100
	}
	if completed <= 0 {
		return 0
	}
	if completed >= total {
		return 100
	}
	return completed * 100 / total
}
