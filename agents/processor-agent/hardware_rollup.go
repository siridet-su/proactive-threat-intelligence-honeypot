package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// hardwareLiveFields is the bounded real-time projection consumed by System
// Health. Raw interface counters, collector semantics, and audit-only fields
// remain outside hardware_live.
var hardwareLiveFields = map[string]struct{}{
	"cpu_percent":         {},
	"cpu_core_percent":    {},
	"mem_percent":         {},
	"mem_total_bytes":     {},
	"mem_available_bytes": {},
	"mem_used_bytes":      {},
	"disk_percent":        {},
	"disk_total_bytes":    {},
	"disk_free_bytes":     {},
	"disk_used_bytes":     {},
	"temperature":         {},
	"net_wlan0_rx_mbps":   {},
	"net_wlan0_tx_mbps":   {},
}

const (
	hardwareRawStream        = "raw:hardware"
	hardwareLiveCollection   = "hardware_live"
	hardwareRollupCollection = "hardware_metrics_1m"
	hardwareRollupResolution = time.Minute
)

type hardwareSample struct {
	at       time.Time
	sensorID string
	values   map[string]any
}

type numericRollup struct {
	count int64
	min   float64
	max   float64
	sum   float64
}

type hardwareAccumulator struct {
	firstAt     time.Time
	lastAt      time.Time
	sampleCount int64
	latest      map[string]any
	numeric     map[string]*numericRollup
}

func normalizeHardwareValue(value any) any {
	text := valueToString(value)
	if number, err := strconv.ParseFloat(text, 64); err == nil {
		return number
	}
	return text
}

func parseHardwareSample(message redis.XMessage) (hardwareSample, bool) {
	values := make(map[string]any, len(message.Values))
	for key, value := range message.Values {
		values[key] = normalizeHardwareValue(value)
	}
	if encoded, ok := values["cpu_core_percent"].(string); ok {
		var cores []float64
		if err := json.Unmarshal([]byte(encoded), &cores); err != nil || len(cores) == 0 {
			return hardwareSample{}, false
		}
		for _, percentage := range cores {
			if math.IsNaN(percentage) || math.IsInf(percentage, 0) {
				return hardwareSample{}, false
			}
		}
		values["cpu_core_percent"] = cores
	}

	unixSeconds, ok := values["timestamp"].(float64)
	if !ok || math.IsNaN(unixSeconds) || math.IsInf(unixSeconds, 0) {
		return hardwareSample{}, false
	}
	whole, fraction := math.Modf(unixSeconds)
	at := time.Unix(int64(whole), int64(fraction*float64(time.Second))).UTC()
	sensorID := strings.TrimSpace(valueToString(values["sensor_id"]))
	if sensorID == "" {
		sensorID = "hardware-sensor"
		values["sensor_id"] = sensorID
	}
	return hardwareSample{at: at, sensorID: sensorID, values: values}, true
}

func buildHardwareLiveDocument(message redis.XMessage, slotCount int) (bson.M, bool) {
	sample, ok := parseHardwareSample(message)
	if !ok || slotCount <= 0 {
		return nil, false
	}

	slot := sample.at.Unix() % int64(slotCount)
	if slot < 0 {
		slot += int64(slotCount)
	}
	document := bson.M{}
	for key, value := range sample.values {
		if _, keep := hardwareLiveFields[key]; keep {
			document[key] = value
		}
	}
	document["_id"] = fmt.Sprintf("%s:%d", sample.sensorID, slot)
	document["schema_version"] = "hardware_live.v2"
	document["sensor_id"] = sample.sensorID
	document["slot"] = slot
	document["timestamp"] = sample.at
	document["sample_unix"] = sample.at.Unix()
	return document, true
}

func writeHardwareLiveSample(
	ctx context.Context,
	mw *MongoWriter,
	message redis.XMessage,
	slotCount int,
) error {
	document, ok := buildHardwareLiveDocument(message, slotCount)
	if !ok {
		return fmt.Errorf("invalid hardware live sample")
	}
	if _, err := mw.db.Collection(hardwareLiveCollection).ReplaceOne(
		ctx,
		bson.M{"_id": document["_id"]},
		document,
		options.Replace().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("upsert hardware live slot %v: %w", document["_id"], err)
	}
	return nil
}

func isHardwareRollupMetric(name string) bool {
	switch name {
	case "cpu_percent", "mem_percent", "mem_pressure_percent", "disk_percent", "temperature":
		return true
	}
	return strings.HasSuffix(name, "_bytes_per_second") ||
		strings.HasSuffix(name, "_packets_per_second") ||
		strings.HasSuffix(name, "_mbps")
}

func (accumulator *hardwareAccumulator) add(sample hardwareSample) {
	if accumulator.sampleCount == 0 || sample.at.Before(accumulator.firstAt) {
		accumulator.firstAt = sample.at
	}
	if accumulator.sampleCount == 0 || !sample.at.Before(accumulator.lastAt) {
		accumulator.lastAt = sample.at
		accumulator.latest = sample.values
	}
	accumulator.sampleCount++

	for name, value := range sample.values {
		if !isHardwareRollupMetric(name) {
			continue
		}
		number, ok := value.(float64)
		if !ok {
			continue
		}
		current := accumulator.numeric[name]
		if current == nil {
			accumulator.numeric[name] = &numericRollup{
				count: 1,
				min:   number,
				max:   number,
				sum:   number,
			}
			continue
		}
		current.count++
		current.sum += number
		if number < current.min {
			current.min = number
		}
		if number > current.max {
			current.max = number
		}
	}
}

func buildHardwareMinuteRollups(
	messages []redis.XMessage,
	bucketStart time.Time,
	retention time.Duration,
) []bson.M {
	bucketStart = bucketStart.UTC().Truncate(hardwareRollupResolution)
	bucketEnd := bucketStart.Add(hardwareRollupResolution)
	bySensor := make(map[string]*hardwareAccumulator)

	for _, message := range messages {
		sample, ok := parseHardwareSample(message)
		if !ok || sample.at.Before(bucketStart) || !sample.at.Before(bucketEnd) {
			continue
		}
		accumulator := bySensor[sample.sensorID]
		if accumulator == nil {
			accumulator = &hardwareAccumulator{numeric: make(map[string]*numericRollup)}
			bySensor[sample.sensorID] = accumulator
		}
		accumulator.add(sample)
	}

	sensorIDs := make([]string, 0, len(bySensor))
	for sensorID := range bySensor {
		sensorIDs = append(sensorIDs, sensorID)
	}
	sort.Strings(sensorIDs)

	documents := make([]bson.M, 0, len(sensorIDs))
	for _, sensorID := range sensorIDs {
		accumulator := bySensor[sensorID]
		document := bson.M{}
		for key, value := range accumulator.latest {
			document[key] = value
		}

		summary := bson.M{}
		for name, metric := range accumulator.numeric {
			summary[name] = bson.M{
				"min": metric.min,
				"avg": metric.sum / float64(metric.count),
				"max": metric.max,
			}
		}

		document["_id"] = fmt.Sprintf("%s:%d", sensorID, bucketStart.Unix())
		document["schema_version"] = "hardware_metrics_1m.v1"
		document["sensor_id"] = sensorID
		document["timestamp"] = bucketStart
		document["bucket_end"] = bucketEnd
		document["resolution_seconds"] = int64(hardwareRollupResolution / time.Second)
		document["sample_count"] = accumulator.sampleCount
		document["sample_first_at"] = accumulator.firstAt
		document["sample_last_at"] = accumulator.lastAt
		document["rollup"] = summary
		document["expires_at"] = bucketStart.Add(retention)
		documents = append(documents, document)
	}
	return documents
}

func hardwareStreamRange(bucketStart time.Time) (string, string) {
	startMillis := bucketStart.UTC().Truncate(hardwareRollupResolution).UnixMilli()
	endMillis := bucketStart.UTC().Truncate(hardwareRollupResolution).Add(hardwareRollupResolution).UnixMilli() - 1
	return fmt.Sprintf("%d-0", startMillis), fmt.Sprintf("%d-999999", endMillis)
}

func writeHardwareRollupBucket(
	ctx context.Context,
	rdb *redis.Client,
	mw *MongoWriter,
	bucketStart time.Time,
	retention time.Duration,
) error {
	startID, endID := hardwareStreamRange(bucketStart)
	messages, err := rdb.XRange(ctx, hardwareRawStream, startID, endID).Result()
	if err != nil {
		return fmt.Errorf("read hardware stream: %w", err)
	}
	documents := buildHardwareMinuteRollups(messages, bucketStart, retention)
	for _, document := range documents {
		if _, err := mw.db.Collection(hardwareRollupCollection).ReplaceOne(
			ctx,
			bson.M{"_id": document["_id"]},
			document,
			options.Replace().SetUpsert(true),
		); err != nil {
			return fmt.Errorf("upsert hardware rollup %v: %w", document["_id"], err)
		}
	}
	if len(documents) > 0 {
		log.Printf(
			"hardware rollup bucket=%s sensors=%d samples=%d",
			bucketStart.UTC().Format(time.RFC3339),
			len(documents),
			len(messages),
		)
	}
	return nil
}

func hardwareRollupLoop(ctx context.Context, rdb *redis.Client, mw *MongoWriter, cfg Config) {
	if !mw.enabled {
		log.Printf("hardware rollup disabled: MongoDB is not configured")
		return
	}

	currentMinute := time.Now().UTC().Truncate(hardwareRollupResolution)
	for offset := cfg.HardwareRollupBackfillMinutes; offset >= 1; offset-- {
		bucketStart := currentMinute.Add(-time.Duration(offset) * hardwareRollupResolution)
		if err := writeHardwareRollupBucket(ctx, rdb, mw, bucketStart, cfg.HardwareRollupRetention); err != nil {
			log.Printf("hardware rollup backfill failed bucket=%s err=%v", bucketStart.Format(time.RFC3339), err)
		}
	}

	for {
		now := time.Now().UTC()
		nextRun := now.Truncate(hardwareRollupResolution).Add(hardwareRollupResolution + 2*time.Second)
		timer := time.NewTimer(time.Until(nextRun))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			bucketStart := time.Now().UTC().Truncate(hardwareRollupResolution).Add(-hardwareRollupResolution)
			if err := writeHardwareRollupBucket(ctx, rdb, mw, bucketStart, cfg.HardwareRollupRetention); err != nil {
				log.Printf("hardware rollup failed bucket=%s err=%v", bucketStart.Format(time.RFC3339), err)
			}
		}
	}
}
