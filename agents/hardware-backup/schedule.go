package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	scheduleCollection    = "backup_schedule_revisions"
	scheduleRunCollection = "backup_schedule_runs"
	scheduleSchemaVersion = "pti.backup_schedule.v1"
	defaultScheduleTime   = "03:30"
	scheduleRetryDelay    = 15 * time.Minute
	scheduleLeaseDuration = 30 * time.Minute
)

var bangkokLocation = time.FixedZone("Asia/Bangkok", 7*60*60)

type scheduleOverride struct {
	StartDate string `bson:"start_date"`
	Days      int    `bson:"days"`
	Time      string `bson:"time"`
}

type backupSchedule struct {
	ID            primitive.ObjectID `bson:"_id"`
	SchemaVersion string             `bson:"schema_version"`
	Sequence      int64              `bson:"sequence"`
	BaseTime      string             `bson:"base_time"`
	Override      *scheduleOverride  `bson:"override"`
}

func loadBackupSchedule(ctx context.Context, database *mongo.Database) (backupSchedule, error) {
	schedule := backupSchedule{BaseTime: defaultScheduleTime}
	err := database.Collection(scheduleCollection).FindOne(ctx, bson.M{},
		options.FindOne().SetSort(bson.D{{Key: "sequence", Value: -1}})).Decode(&schedule)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return backupSchedule{BaseTime: defaultScheduleTime}, nil
	}
	if err != nil {
		return backupSchedule{}, fmt.Errorf("read backup schedule: %w", err)
	}
	if schedule.SchemaVersion != scheduleSchemaVersion {
		return backupSchedule{}, fmt.Errorf("unsupported backup schedule schema")
	}
	if _, _, err := parseDailyTime(schedule.BaseTime); err != nil {
		return backupSchedule{}, err
	}
	if schedule.Override != nil {
		if err := validateScheduleOverride(*schedule.Override); err != nil {
			return backupSchedule{}, err
		}
	}
	return schedule, nil
}

func parseDailyTime(value string) (int, int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, 0, fmt.Errorf("invalid daily backup time")
	}
	hour, hourErr := strconv.Atoi(value[:2])
	minute, minuteErr := strconv.Atoi(value[3:])
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("invalid daily backup time")
	}
	return hour, minute, nil
}

func validateScheduleOverride(override scheduleOverride) error {
	start, err := time.ParseInLocation("2006-01-02", override.StartDate, bangkokLocation)
	if err != nil || start.Format("2006-01-02") != override.StartDate || override.Days < 1 || override.Days > 90 {
		return fmt.Errorf("invalid temporary backup schedule")
	}
	_, _, err = parseDailyTime(override.Time)
	return err
}

func effectiveScheduleTime(schedule backupSchedule, localDay string) string {
	if schedule.Override == nil {
		return schedule.BaseTime
	}
	start, _ := time.ParseInLocation("2006-01-02", schedule.Override.StartDate, bangkokLocation)
	end := start.AddDate(0, 0, schedule.Override.Days).Format("2006-01-02")
	if localDay >= schedule.Override.StartDate && localDay < end {
		return schedule.Override.Time
	}
	return schedule.BaseTime
}

func dueScheduleDay(schedule backupSchedule, now time.Time) (string, bool) {
	localNow := now.In(bangkokLocation)
	day := localNow.Format("2006-01-02")
	hour, minute, _ := parseDailyTime(effectiveScheduleTime(schedule, day))
	due := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), hour, minute, 0, 0, bangkokLocation)
	return day, !localNow.Before(due)
}

func tryClaimScheduleRun(ctx context.Context, runs *mongo.Collection, day, workerID, revision string, now time.Time) (bool, error) {
	filter := bson.M{"_id": day, "$or": bson.A{
		bson.M{"status": bson.M{"$exists": false}},
		bson.M{"status": "failed", "retry_after": bson.M{"$lte": now}},
		bson.M{"status": "running", "heartbeat_at": bson.M{"$lt": now.Add(-scheduleLeaseDuration)}},
	}}
	update := bson.M{"$set": bson.M{
		"status": "running", "worker_id": workerID, "schedule_revision": revision,
		"started_at": now, "heartbeat_at": now, "completed_at": nil, "error": nil,
	}}
	result, err := runs.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim backup schedule day: %w", err)
	}
	return result.ModifiedCount > 0 || result.UpsertedCount > 0, nil
}

func runDueBackupSchedule(ctx context.Context, database *mongo.Database, cfg Config, manifests, snapshots *mongo.Collection, workerID string) (bool, error) {
	schedule, err := loadBackupSchedule(ctx, database)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	day, due := dueScheduleDay(schedule, now)
	if !due {
		return false, nil
	}
	revision := "default"
	if !schedule.ID.IsZero() {
		revision = schedule.ID.Hex()
	}
	runs := database.Collection(scheduleRunCollection)
	claimed, err := tryClaimScheduleRun(ctx, runs, day, workerID, revision, now)
	if err != nil || !claimed {
		return false, err
	}
	log.Printf("backup scheduled run started local_day=%s revision=%s", day, revision)
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				_, heartbeatErr := runs.UpdateOne(heartbeatCtx,
					bson.M{"_id": day, "status": "running", "worker_id": workerID},
					bson.M{"$set": bson.M{"heartbeat_at": time.Now().UTC()}},
				)
				if heartbeatErr != nil {
					log.Printf("backup schedule heartbeat failed: %v", heartbeatErr)
				}
			}
		}
	}()
	runErr := runScheduledBackup(ctx, cfg, database, manifests, snapshots)
	stopHeartbeat()
	<-heartbeatDone
	finished := time.Now().UTC()
	fields := bson.M{"completed_at": finished, "heartbeat_at": finished}
	if runErr != nil {
		fields["status"] = "failed"
		fields["retry_after"] = finished.Add(scheduleRetryDelay)
		fields["error"] = strings.TrimSpace(runErr.Error())
	} else {
		fields["status"] = "success"
		fields["retry_after"] = nil
		fields["error"] = nil
	}
	_, updateErr := runs.UpdateOne(ctx,
		bson.M{"_id": day, "status": "running", "worker_id": workerID},
		bson.M{"$set": fields})
	if updateErr != nil {
		return true, fmt.Errorf("record backup schedule result: %w", updateErr)
	}
	if runErr != nil {
		return true, fmt.Errorf("scheduled backup: %w", runErr)
	}
	log.Printf("backup scheduled run completed local_day=%s", day)
	return true, nil
}
