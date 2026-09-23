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

const archiveSchemaVersion = "pti.hardware_metrics_1m_backup.v1"

type archiveHeader struct {
	Marker        string `json:"_pti_backup"`
	SchemaVersion string `json:"schema_version"`
	Collection    string `json:"collection"`
	DayStart      string `json:"day_start"`
	DayEnd        string `json:"day_end"`
}

type ArchiveResult struct {
	Path          string
	DocumentCount int64
	SizeBytes     int64
	SHA1          string
	SHA256        string
}

func writeDayArchive(
	ctx context.Context,
	collection *mongo.Collection,
	cfg Config,
	dayStart time.Time,
) (ArchiveResult, error) {
	dayStart = dayStart.UTC().Truncate(24 * time.Hour)
	dayEnd := dayStart.Add(24 * time.Hour)
	if err := os.MkdirAll(cfg.BackupRoot, 0o700); err != nil {
		return ArchiveResult{}, fmt.Errorf("create backup root: %w", err)
	}

	temporary, err := os.CreateTemp(cfg.BackupRoot, "hardware-metrics-*.jsonl.gz")
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
		Marker:        "hardware_metrics_1m",
		SchemaVersion: archiveSchemaVersion,
		Collection:    cfg.Collection,
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

	query := bson.M{
		"timestamp": bson.M{
			"$gte": dayStart,
			"$lt":  dayEnd,
		},
	}
	cursor, err := collection.Find(ctx, query, options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: 1}, {Key: "_id", Value: 1}}).
		SetBatchSize(512))
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("read %s for %s: %w", cfg.Collection, dayStart.Format("2006-01-02"), err)
	}
	defer cursor.Close(ctx)

	var documentCount int64
	for cursor.Next(ctx) {
		document := bson.M{}
		if err := cursor.Decode(&document); err != nil {
			return ArchiveResult{}, fmt.Errorf("decode %s document: %w", cfg.Collection, err)
		}
		encoded, err := bson.MarshalExtJSON(document, true, false)
		if err != nil {
			return ArchiveResult{}, fmt.Errorf("encode %s document: %w", cfg.Collection, err)
		}
		if _, err := buffered.Write(encoded); err != nil {
			return ArchiveResult{}, fmt.Errorf("write %s document: %w", cfg.Collection, err)
		}
		if err := buffered.WriteByte('\n'); err != nil {
			return ArchiveResult{}, fmt.Errorf("write %s document separator: %w", cfg.Collection, err)
		}
		documentCount++
	}
	if err := cursor.Err(); err != nil {
		return ArchiveResult{}, fmt.Errorf("iterate %s documents: %w", cfg.Collection, err)
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
	return filepath.ToSlash(filepath.Join(
		"hardware_metrics_1m",
		dayStart.UTC().Format("2006"),
		dayStart.UTC().Format("01"),
		dayStart.UTC().Format("02"),
		"rollup.jsonl.gz",
	))
}
