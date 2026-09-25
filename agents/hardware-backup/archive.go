package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const archiveSchemaVersion = "pti.backup.v2"

type archiveHeader struct {
	Marker        string   `json:"_pti_backup"`
	SchemaVersion string   `json:"schema_version"`
	TargetID      string   `json:"target_id"`
	Collections   []string `json:"collections"`
	DayStart      string   `json:"day_start"`
	DayEnd        string   `json:"day_end"`
}

type archiveRecord struct {
	Collection string          `json:"collection"`
	Document   json.RawMessage `json:"document"`
}

type ArchiveResult struct {
	Path          string
	DocumentCount int64
	SizeBytes     int64
	SHA1          string
	SHA256        string
}

// writeDayArchive keeps the original helper available for focused tests and
// older callers. New runs use writeTargetDayArchive so a logical target can
// contain more than one authoritative collection.
func writeDayArchive(
	ctx context.Context,
	collection *mongo.Collection,
	cfg Config,
	dayStart time.Time,
) (ArchiveResult, error) {
	target := BackupTarget{
		ID:     cfg.Collection,
		Prefix: cfg.Collection,
		Sources: []ArchiveSource{{
			Collection: cfg.Collection,
			TimeFields: []string{"timestamp"},
			SortField:  "timestamp",
		}},
	}
	return writeTargetDayArchive(ctx, collection.Database(), cfg, target, dayStart)
}

func writeTargetDayArchive(
	ctx context.Context,
	database *mongo.Database,
	cfg Config,
	target BackupTarget,
	dayStart time.Time,
) (ArchiveResult, error) {
	dayStart = dayStart.UTC().Truncate(24 * time.Hour)
	dayEnd := dayStart.Add(24 * time.Hour)
	if err := os.MkdirAll(cfg.BackupRoot, 0o700); err != nil {
		return ArchiveResult{}, fmt.Errorf("create backup root: %w", err)
	}

	temporary, err := os.CreateTemp(cfg.BackupRoot, "backup-"+target.ID+"-*.jsonl.gz")
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("create archive temp file: %w", err)
	}
	temporaryPath := temporary.Name()
	keepFile := false
	defer func() {
		_ = temporary.Close()
		if !keepFile {
			_ = os.Remove(temporaryPath)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(temporary, gzip.BestCompression)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("create gzip writer: %w", err)
	}
	buffered := bufio.NewWriterSize(gzipWriter, 64*1024)
	header := archiveHeader{
		Marker:        "pti_backup",
		SchemaVersion: archiveSchemaVersion,
		TargetID:      target.ID,
		Collections:   backupTargetCollectionNames(target),
		DayStart:      dayStart.Format(time.RFC3339),
		DayEnd:        dayEnd.Format(time.RFC3339),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("encode archive header: %w", err)
	}
	if _, err := buffered.Write(append(headerBytes, '\n')); err != nil {
		return ArchiveResult{}, fmt.Errorf("write archive header: %w", err)
	}

	var documentCount int64
	for _, source := range target.Sources {
		count, err := writeSourceArchive(ctx, buffered, database.Collection(source.Collection), source, dayStart, dayEnd)
		if err != nil {
			return ArchiveResult{}, err
		}
		documentCount += count
	}
	if err := buffered.Flush(); err != nil {
		return ArchiveResult{}, fmt.Errorf("flush archive: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return ArchiveResult{}, fmt.Errorf("close gzip archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return ArchiveResult{}, fmt.Errorf("sync archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return ArchiveResult{}, fmt.Errorf("close archive: %w", err)
	}

	sha1Hex, sha256Hex, size, err := hashFile(temporaryPath)
	if err != nil {
		return ArchiveResult{}, err
	}
	keepFile = true
	return ArchiveResult{
		Path:          temporaryPath,
		DocumentCount: documentCount,
		SizeBytes:     size,
		SHA1:          sha1Hex,
		SHA256:        sha256Hex,
	}, nil
}

func writeSourceArchive(
	ctx context.Context,
	writer *bufio.Writer,
	collection *mongo.Collection,
	source ArchiveSource,
	dayStart time.Time,
	dayEnd time.Time,
) (int64, error) {
	query := archiveSourceQuery(source, dayStart, dayEnd)
	sortField := source.SortField
	if sortField == "" && len(source.TimeFields) > 0 {
		sortField = source.TimeFields[0]
	}
	findOptions := options.Find().SetBatchSize(512)
	if sortField != "" {
		findOptions.SetSort(bson.D{{Key: sortField, Value: 1}, {Key: "_id", Value: 1}})
	}
	cursor, err := collection.Find(ctx, query, findOptions)
	if err != nil {
		return 0, fmt.Errorf("read %s for %s: %w", source.Collection, dayStart.Format("2006-01-02"), err)
	}
	defer cursor.Close(ctx)

	var documentCount int64
	for cursor.Next(ctx) {
		document := bson.M{}
		if err := cursor.Decode(&document); err != nil {
			return 0, fmt.Errorf("decode %s document: %w", source.Collection, err)
		}
		documentBytes, err := bson.MarshalExtJSON(document, true, false)
		if err != nil {
			return 0, fmt.Errorf("encode %s document: %w", source.Collection, err)
		}
		recordBytes, err := json.Marshal(archiveRecord{
			Collection: source.Collection,
			Document:   documentBytes,
		})
		if err != nil {
			return 0, fmt.Errorf("encode %s archive record: %w", source.Collection, err)
		}
		if _, err := writer.Write(append(recordBytes, '\n')); err != nil {
			return 0, fmt.Errorf("write %s document: %w", source.Collection, err)
		}
		documentCount++
	}
	if err := cursor.Err(); err != nil {
		return 0, fmt.Errorf("iterate %s documents: %w", source.Collection, err)
	}
	return documentCount, nil
}

func archiveSourceQuery(source ArchiveSource, dayStart, dayEnd time.Time) bson.M {
	dateRange := bson.M{"$gte": dayStart, "$lt": dayEnd}
	if len(source.TimeFields) == 0 {
		return bson.M{}
	}
	if len(source.TimeFields) == 1 {
		return bson.M{source.TimeFields[0]: dateRange}
	}
	conditions := make(bson.A, 0, len(source.TimeFields))
	for _, field := range source.TimeFields {
		conditions = append(conditions, bson.M{field: dateRange})
	}
	return bson.M{"$or": conditions}
}

func hashFile(path string) (sha1Hex, sha256Hex string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open archive for hashing: %w", err)
	}
	defer file.Close()

	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	bytes, err := io.Copy(io.MultiWriter(sha1Hash, sha256Hash), file)
	if err != nil {
		return "", "", 0, fmt.Errorf("hash archive: %w", err)
	}
	return hex.EncodeToString(sha1Hash.Sum(nil)), hex.EncodeToString(sha256Hash.Sum(nil)), bytes, nil
}

func archiveObjectName(dayStart time.Time) string {
	return archiveObjectNameForTarget(BackupTarget{ID: hardwareBackupTargetID, Prefix: hardwareBackupTargetID}, dayStart)
}

func archiveObjectNameForTarget(target BackupTarget, dayStart time.Time) string {
	filename := "archive.jsonl.gz"
	if target.ID == hardwareBackupTargetID {
		filename = "rollup.jsonl.gz"
	}
	return filepath.ToSlash(filepath.Join(
		target.Prefix,
		dayStart.UTC().Format("2006"),
		dayStart.UTC().Format("01"),
		dayStart.UTC().Format("02"),
		filename,
	))
}
