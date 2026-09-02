package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var metricNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9]+`)

type networkSample struct {
	takenAt time.Time
	byName  map[string]net.IOCountersStat
}

func requireEnv(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("%s must be set in the service environment", key)
	}
	return value
}

func requirePositiveIntEnv(key string) int {
	value, err := strconv.Atoi(requireEnv(key))
	if err != nil || value <= 0 {
		log.Fatalf("%s must be a positive integer", key)
	}
	return value
}

func csvValues(value string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func metricInterfaceName(name string) string {
	return strings.Trim(metricNameSanitizer.ReplaceAllString(name, "_"), "_")
}

// getTemp reads the Raspberry Pi CPU temperature
func getTemp() float64 {
	data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0.0
	}
	tempStr := strings.TrimSpace(string(data))
	tempInt, err := strconv.Atoi(tempStr)
	if err != nil {
		return 0.0
	}
	// The value is in millidegrees Celsius
	return float64(tempInt) / 1000.0
}

func main() {
	snapshotJSON := flag.Bool(
		"snapshot-json",
		false,
		"print one warmed read-only metric snapshot without Redis and exit",
	)
	snapshotInterval := flag.Duration(
		"snapshot-interval",
		time.Second,
		"warm-up interval used by --snapshot-json",
	)
	snapshotInterfaces := flag.String(
		"snapshot-interfaces",
		"wlan0,tailscale0,lo",
		"comma-separated interface allowlist used by --snapshot-json",
	)
	snapshotPrimaryInterface := flag.String(
		"snapshot-primary-interface",
		"wlan0",
		"primary physical interface used by --snapshot-json",
	)
	flag.Parse()

	if *snapshotJSON {
		if err := emitSnapshot(
			*snapshotInterval,
			csvValues(*snapshotInterfaces),
			strings.TrimSpace(*snapshotPrimaryInterface),
		); err != nil {
			log.Fatal(err)
		}
		return
	}

	redisAddr := requireEnv("REDIS_ADDR")
	redisPass := os.Getenv("REDIS_PASSWORD")
	redisDBStr := requireEnv("REDIS_DB")

	db, _ := strconv.Atoi(redisDBStr)

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPass,
		DB:       db,
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	interfaces := csvValues(requireEnv("NETWORK_INTERFACES"))
	primaryInterface := requireEnv("NETWORK_PRIMARY_INTERFACE")
	sampleSeconds := requirePositiveIntEnv("NETWORK_SAMPLE_SECONDS")

	log.Printf(
		"Hardware Agent started, stream=raw:hardware interval=%ds primary_interface=%s interfaces=%s",
		sampleSeconds,
		primaryInterface,
		strings.Join(interfaces, ","),
	)

	ticker := time.NewTicker(time.Duration(sampleSeconds) * time.Second)
	defer ticker.Stop()

	previousNetwork := pushMetrics(ctx, rdb, nil, interfaces, primaryInterface)

	for {
		<-ticker.C
		previousNetwork = pushMetrics(ctx, rdb, previousNetwork, interfaces, primaryInterface)
	}
}

func pushMetrics(
	ctx context.Context,
	rdb *redis.Client,
	previousNetwork *networkSample,
	interfaces []string,
	primaryInterface string,
) *networkSample {
	values, currentNetwork := collectHardwareMetrics(
		previousNetwork,
		interfaces,
		primaryInterface,
		time.Now(),
	)

	_, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: "raw:hardware",
		MaxLen: 5000,
		Approx: true,
		Values: values,
	}).Result()

	if err != nil {
		log.Printf("Error pushing to Redis: %v", err)
	} else {
		log.Printf("Pushed detailed metrics successfully.")
	}

	return currentNetwork
}

func collectHardwareMetrics(
	previousNetwork *networkSample,
	interfaces []string,
	primaryInterface string,
	takenAt time.Time,
) (map[string]interface{}, *networkSample) {
	values := map[string]interface{}{
		"timestamp": takenAt.Unix(),
	}

	// 1. Memory Metrics
	if v, err := mem.VirtualMemory(); err == nil && v != nil {
		addMemoryMetrics(values, v)
	}

	// 2. CPU Metrics
	if c, err := cpu.Percent(0, false); err == nil && len(c) > 0 {
		values["cpu_percent"] = fmt.Sprintf("%.2f", c[0])
	}

	// Per-core CPU % removed to save database space

	// 3. Disk Metrics (root /)
	if d, err := disk.Usage("/"); err == nil && d != nil {
		values["disk_used_bytes"] = d.Used
		values["disk_percent"] = fmt.Sprintf("%.2f", d.UsedPercent)
	}

	// 4. Keep physical and overlay metrics separate. Tailscale traffic is also
	// carried by wlan0, so adding both interfaces would double-count it.
	currentNetwork := collectNetworkMetrics(
		values,
		previousNetwork,
		interfaces,
		primaryInterface,
		takenAt,
	)

	// 5. Temperature
	temp := getTemp()
	values["temperature"] = fmt.Sprintf("%.2f", temp)

	return values, currentNetwork
}

func addMemoryMetrics(values map[string]interface{}, memory *mem.VirtualMemoryStat) {
	// Preserve the historical gopsutil fields for existing dashboards.  The
	// explicit pressure fields use total-available, matching psutil and the
	// experimental telemetry schema used by model training.
	values["mem_total_bytes"] = memory.Total
	values["mem_available_bytes"] = memory.Available
	values["mem_used_bytes"] = memory.Used
	values["mem_percent"] = fmt.Sprintf("%.2f", memory.UsedPercent)
	values["mem_used_semantics"] = "legacy_total_minus_free_buffers_cached"
	pressureUsed := uint64(0)
	if memory.Total >= memory.Available {
		pressureUsed = memory.Total - memory.Available
	}
	pressurePercent := 0.0
	if memory.Total > 0 {
		pressurePercent = float64(pressureUsed) / float64(memory.Total) * 100
	}
	values["mem_pressure_used_bytes"] = pressureUsed
	values["mem_pressure_percent"] = fmt.Sprintf("%.2f", pressurePercent)
	values["mem_pressure_semantics"] = "total_minus_available"
}

func emitSnapshot(
	interval time.Duration,
	interfaces []string,
	primaryInterface string,
) error {
	if interval < 100*time.Millisecond || interval > 60*time.Second {
		return fmt.Errorf("snapshot interval must be between 100ms and 60s")
	}
	if len(interfaces) == 0 {
		return fmt.Errorf("snapshot interfaces must not be empty")
	}
	primaryFound := false
	for _, interfaceName := range interfaces {
		if interfaceName == primaryInterface {
			primaryFound = true
			break
		}
	}
	if !primaryFound {
		return fmt.Errorf("snapshot primary interface must be in the interface allowlist")
	}

	_, previousNetwork := collectHardwareMetrics(
		nil,
		interfaces,
		primaryInterface,
		time.Now(),
	)
	time.Sleep(interval)
	values, _ := collectHardwareMetrics(
		previousNetwork,
		interfaces,
		primaryInterface,
		time.Now(),
	)
	document := map[string]interface{}{
		"schema_version":          "hardware_agent_snapshot.v1",
		"mode":                    "read_only_no_sink",
		"requested_interval_ms":   interval.Milliseconds(),
		"redis_write_attempted":   false,
		"mongo_write_attempted":   false,
		"production_service_used": false,
		"metrics":                 values,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func collectNetworkMetrics(
	values map[string]interface{},
	previous *networkSample,
	interfaces []string,
	primaryInterface string,
	takenAt time.Time,
) *networkSample {
	allCounters, err := net.IOCounters(true)
	if err != nil {
		log.Printf("Error reading network counters: %v", err)
		return previous
	}

	available := make(map[string]net.IOCountersStat, len(allCounters))
	for _, counter := range allCounters {
		available[counter.Name] = counter
	}

	current := &networkSample{takenAt: takenAt, byName: make(map[string]net.IOCountersStat)}
	values["network_primary_interface"] = primaryInterface
	values["network_interfaces"] = strings.Join(interfaces, ",")

	elapsedSeconds := 0.0
	if previous != nil {
		elapsedSeconds = takenAt.Sub(previous.takenAt).Seconds()
		if elapsedSeconds > 0 {
			values["network_sample_interval_seconds"] = fmt.Sprintf("%.3f", elapsedSeconds)
		}
	}

	for _, interfaceName := range interfaces {
		counter, exists := available[interfaceName]
		prefix := "net_" + metricInterfaceName(interfaceName) + "_"
		if !exists {
			values[prefix+"up"] = 0
			continue
		}

		current.byName[interfaceName] = counter
		values[prefix+"up"] = 1
		addInterfaceMetrics(values, prefix, counter, nil, 0)

		// Preserve the old fields for current dashboards, but define them as the
		// primary physical interface counters rather than all interfaces combined.
		if interfaceName == primaryInterface {
			values["net_bytes_sent"] = counter.BytesSent
			values["net_bytes_recv"] = counter.BytesRecv
			values["net_packets_sent"] = counter.PacketsSent
			values["net_packets_recv"] = counter.PacketsRecv
		}

		previousCounter, hadPrevious := net.IOCountersStat{}, false
		if previous != nil {
			previousCounter, hadPrevious = previous.byName[interfaceName]
		}
		if !hadPrevious || elapsedSeconds <= 0 {
			continue
		}

		addInterfaceMetrics(values, prefix, counter, &previousCounter, elapsedSeconds)
	}

	return current
}

func addInterfaceMetrics(
	values map[string]interface{},
	prefix string,
	counter net.IOCountersStat,
	previous *net.IOCountersStat,
	elapsedSeconds float64,
) {
	values[prefix+"rx_bytes_total"] = counter.BytesRecv
	values[prefix+"tx_bytes_total"] = counter.BytesSent
	values[prefix+"rx_packets_total"] = counter.PacketsRecv
	values[prefix+"tx_packets_total"] = counter.PacketsSent
	values[prefix+"rx_errors_total"] = counter.Errin
	values[prefix+"tx_errors_total"] = counter.Errout
	values[prefix+"rx_dropped_total"] = counter.Dropin
	values[prefix+"tx_dropped_total"] = counter.Dropout

	if previous == nil || elapsedSeconds <= 0 {
		return
	}
	if counter.BytesRecv >= previous.BytesRecv && counter.BytesSent >= previous.BytesSent {
		rxBytesPerSecond := float64(counter.BytesRecv-previous.BytesRecv) / elapsedSeconds
		txBytesPerSecond := float64(counter.BytesSent-previous.BytesSent) / elapsedSeconds
		values[prefix+"rx_bytes_per_second"] = fmt.Sprintf("%.3f", rxBytesPerSecond)
		values[prefix+"tx_bytes_per_second"] = fmt.Sprintf("%.3f", txBytesPerSecond)
		values[prefix+"rx_mbps"] = fmt.Sprintf("%.6f", rxBytesPerSecond*8/1_000_000)
		values[prefix+"tx_mbps"] = fmt.Sprintf("%.6f", txBytesPerSecond*8/1_000_000)
	}
	if counter.PacketsRecv >= previous.PacketsRecv && counter.PacketsSent >= previous.PacketsSent {
		rxPacketsPerSecond := float64(counter.PacketsRecv-previous.PacketsRecv) / elapsedSeconds
		txPacketsPerSecond := float64(counter.PacketsSent-previous.PacketsSent) / elapsedSeconds
		values[prefix+"rx_packets_per_second"] = fmt.Sprintf("%.3f", rxPacketsPerSecond)
		values[prefix+"tx_packets_per_second"] = fmt.Sprintf("%.3f", txPacketsPerSecond)
	}
}
