package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
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

func getenv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getenvPositiveInt(key string, fallback int) int {
	value, err := strconv.Atoi(getenv(key, strconv.Itoa(fallback)))
	if err != nil || value <= 0 {
		return fallback
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
	_ = godotenv.Load("/etc/honeypot-agent.env")
	_ = godotenv.Load()

	redisAddr := getenv("REDIS_ADDR", "127.0.0.1:6379")
	redisPass := getenv("REDIS_PASSWORD", "")
	redisDBStr := getenv("REDIS_DB", "0")

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

	interfaces := csvValues(getenv("NETWORK_INTERFACES", "wlan0,tailscale0"))
	primaryInterface := getenv("NETWORK_PRIMARY_INTERFACE", "wlan0")
	sampleSeconds := getenvPositiveInt("NETWORK_SAMPLE_SECONDS", 30)

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
	values := map[string]interface{}{
		"timestamp": time.Now().Unix(),
	}

	// 1. Memory Metrics
	if v, err := mem.VirtualMemory(); err == nil && v != nil {
		values["mem_used_bytes"] = v.Used
		values["mem_percent"] = fmt.Sprintf("%.2f", v.UsedPercent)
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
	currentNetwork := collectNetworkMetrics(values, previousNetwork, interfaces, primaryInterface, time.Now())

	// 5. Temperature
	temp := getTemp()
	values["temperature"] = fmt.Sprintf("%.2f", temp)

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
		values[prefix+"rx_bytes_total"] = counter.BytesRecv
		values[prefix+"tx_bytes_total"] = counter.BytesSent

		// Preserve the old fields for current dashboards, but define them as the
		// primary physical interface counters rather than all interfaces combined.
		if interfaceName == primaryInterface {
			values["net_bytes_sent"] = counter.BytesSent
			values["net_bytes_recv"] = counter.BytesRecv
		}

		previousCounter, hadPrevious := net.IOCountersStat{}, false
		if previous != nil {
			previousCounter, hadPrevious = previous.byName[interfaceName]
		}
		if !hadPrevious || elapsedSeconds <= 0 {
			continue
		}

		// Skip one rate sample after an interface reset/counter wrap.
		if counter.BytesRecv < previousCounter.BytesRecv || counter.BytesSent < previousCounter.BytesSent {
			continue
		}

		rxBytesPerSecond := float64(counter.BytesRecv-previousCounter.BytesRecv) / elapsedSeconds
		txBytesPerSecond := float64(counter.BytesSent-previousCounter.BytesSent) / elapsedSeconds

		values[prefix+"rx_bytes_per_second"] = fmt.Sprintf("%.3f", rxBytesPerSecond)
		values[prefix+"tx_bytes_per_second"] = fmt.Sprintf("%.3f", txBytesPerSecond)
		values[prefix+"rx_mbps"] = fmt.Sprintf("%.6f", rxBytesPerSecond*8/1_000_000)
		values[prefix+"tx_mbps"] = fmt.Sprintf("%.6f", txBytesPerSecond*8/1_000_000)
	}

	return current
}
