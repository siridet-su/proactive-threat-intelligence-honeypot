package main

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
)

func hardwareMessage(id string, timestamp int64, sensorID string, cpu string) redis.XMessage {
	return redis.XMessage{
		ID: id,
		Values: map[string]any{
			"timestamp":           timestamp,
			"sensor_id":           sensorID,
			"cpu_percent":         cpu,
			"cpu_core_percent":    "[12.5,25.0]",
			"mem_percent":         "25.0",
			"mem_total_bytes":     "8000",
			"mem_available_bytes": "6000",
			"mem_used_bytes":      "2000",
			"disk_percent":        "40.0",
			"disk_total_bytes":    "10000",
			"disk_free_bytes":     "6000",
			"disk_used_bytes":     "4000",
			"temperature":         "52.0",
			"net_wlan0_rx_mbps":   "0.5",
			"net_wlan0_tx_mbps":   "0.25",
			"net_bytes_recv":      "1000",
			"network_interfaces":  "wlan0",
		},
	}
}

func TestBuildHardwareMinuteRollupsAggregatesAndKeepsLatest(t *testing.T) {
	bucket := time.Date(2026, 9, 10, 1, 2, 0, 0, time.UTC)
	messages := []redis.XMessage{
		hardwareMessage("1-0", bucket.Add(5*time.Second).Unix(), "pi-1", "10"),
		hardwareMessage("2-0", bucket.Add(55*time.Second).Unix(), "pi-1", "30"),
		hardwareMessage("3-0", bucket.Add(time.Minute).Unix(), "pi-1", "99"),
	}

	documents := buildHardwareMinuteRollups(messages, bucket, 30*24*time.Hour)
	if len(documents) != 1 {
		t.Fatalf("rollup count = %d, want 1", len(documents))
	}
	document := documents[0]
	if document["_id"] != "pi-1:1789002120" {
		t.Fatalf("unexpected id: %#v", document["_id"])
	}
	if document["sample_count"] != int64(2) {
		t.Fatalf("sample_count = %#v, want 2", document["sample_count"])
	}
	if document["cpu_percent"] != float64(30) {
		t.Fatalf("latest cpu_percent = %#v, want 30", document["cpu_percent"])
	}
	if document["timestamp"] != bucket || document["bucket_end"] != bucket.Add(time.Minute) {
		t.Fatalf("bucket timestamps are incorrect: %#v", document)
	}
	if document["expires_at"] != bucket.Add(30*24*time.Hour) {
		t.Fatalf("expires_at = %#v", document["expires_at"])
	}

	summary, ok := document["rollup"].(bson.M)
	if !ok {
		t.Fatalf("rollup summary type = %T", document["rollup"])
	}
	cpuSummary, ok := summary["cpu_percent"].(bson.M)
	if !ok {
		t.Fatalf("cpu summary type = %T", summary["cpu_percent"])
	}
	if cpuSummary["min"] != float64(10) || cpuSummary["avg"] != float64(20) || cpuSummary["max"] != float64(30) {
		t.Fatalf("cpu summary = %#v", cpuSummary)
	}
	if _, exists := summary["net_bytes_recv"]; exists {
		t.Fatal("monotonic counters must not be averaged")
	}
}

func TestBuildHardwareMinuteRollupsSeparatesSensors(t *testing.T) {
	bucket := time.Date(2026, 9, 10, 1, 2, 0, 0, time.UTC)
	documents := buildHardwareMinuteRollups([]redis.XMessage{
		hardwareMessage("1-0", bucket.Add(time.Second).Unix(), "pi-b", "20"),
		hardwareMessage("2-0", bucket.Add(2*time.Second).Unix(), "pi-a", "10"),
	}, bucket, time.Hour)

	if len(documents) != 2 {
		t.Fatalf("rollup count = %d, want 2", len(documents))
	}
	if documents[0]["sensor_id"] != "pi-a" || documents[1]["sensor_id"] != "pi-b" {
		t.Fatalf("rollups are not sorted/separated by sensor: %#v", documents)
	}
}

func TestHardwareStreamRangeCoversExactlyOneMinute(t *testing.T) {
	bucket := time.UnixMilli(1_789_002_120_000).UTC()
	start, end := hardwareStreamRange(bucket)
	if start != "1789002120000-0" || end != "1789002179999-999999" {
		t.Fatalf("range = %q..%q", start, end)
	}
}

func TestParseHardwareSampleRejectsMissingTimestamp(t *testing.T) {
	if _, ok := parseHardwareSample(redis.XMessage{Values: map[string]any{"cpu_percent": "1"}}); ok {
		t.Fatal("sample without timestamp must be rejected")
	}
}

func TestBuildHardwareLiveDocumentUsesFixedRingSlot(t *testing.T) {
	at := time.Unix(1_789_002_125, 0).UTC()
	document, ok := buildHardwareLiveDocument(
		hardwareMessage("1-0", at.Unix(), "pi-1", "12.5"),
		30,
	)
	if !ok {
		t.Fatal("valid hardware sample was rejected")
	}
	if document["_id"] != "pi-1:5" || document["slot"] != int64(5) {
		t.Fatalf("unexpected ring identity: %#v", document)
	}
	if document["timestamp"] != at || document["sample_unix"] != at.Unix() {
		t.Fatalf("unexpected sample time: %#v", document)
	}
	if document["cpu_percent"] != float64(12.5) {
		t.Fatalf("cpu_percent = %#v, want 12.5", document["cpu_percent"])
	}
	if document["schema_version"] != "hardware_live.v2" {
		t.Fatalf("schema version = %#v", document["schema_version"])
	}
	cores, ok := document["cpu_core_percent"].([]float64)
	if !ok || len(cores) != 2 || cores[0] != 12.5 || cores[1] != 25 {
		t.Fatalf("per-core CPU payload = %#v", document["cpu_core_percent"])
	}
	if document["mem_total_bytes"] != float64(8000) || document["mem_available_bytes"] != float64(6000) || document["disk_total_bytes"] != float64(10000) || document["disk_free_bytes"] != float64(6000) {
		t.Fatalf("realtime capacity fields missing: %#v", document)
	}
	if _, exists := document["net_bytes_recv"]; exists {
		t.Fatal("raw network counters must not be copied to hardware_live")
	}
	if _, exists := document["network_interfaces"]; exists {
		t.Fatal("raw interface metadata must not be copied to hardware_live")
	}

	next, ok := buildHardwareLiveDocument(
		hardwareMessage("2-0", at.Add(30*time.Second).Unix(), "pi-1", "20"),
		30,
	)
	if !ok || next["_id"] != document["_id"] {
		t.Fatalf("ring slot was not reused after 30 seconds: %#v", next)
	}
}
