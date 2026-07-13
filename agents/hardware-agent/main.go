package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

func getenv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
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

	log.Println("Hardware Agent started, pushing detailed metrics to Redis stream: raw:hardware")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	pushMetrics(ctx, rdb)

	for {
		<-ticker.C
		pushMetrics(ctx, rdb)
	}
}

func pushMetrics(ctx context.Context, rdb *redis.Client) {
	values := map[string]interface{}{
		"timestamp": time.Now().Unix(),
	}

	// 1. Memory Metrics
	if v, err := mem.VirtualMemory(); err == nil && v != nil {
		values["mem_total_bytes"] = v.Total
		values["mem_used_bytes"] = v.Used
		values["mem_available_bytes"] = v.Available
		values["mem_free_bytes"] = v.Free
		values["mem_percent"] = fmt.Sprintf("%.2f", v.UsedPercent)
	}

	// 2. CPU Metrics
	if c, err := cpu.Percent(0, false); err == nil && len(c) > 0 {
		values["cpu_percent"] = fmt.Sprintf("%.2f", c[0])
	}
	
	// Per-core CPU %
	if perCore, err := cpu.Percent(0, true); err == nil {
		for i, corePercent := range perCore {
			values[fmt.Sprintf("cpu_core_%d_percent", i)] = fmt.Sprintf("%.2f", corePercent)
		}
		values["cpu_cores"] = len(perCore)
	}

	// 3. Disk Metrics (root /)
	if d, err := disk.Usage("/"); err == nil && d != nil {
		values["disk_total_bytes"] = d.Total
		values["disk_used_bytes"] = d.Used
		values["disk_free_bytes"] = d.Free
		values["disk_percent"] = fmt.Sprintf("%.2f", d.UsedPercent)
	}

	// 4. Network Metrics (all interfaces combined)
	if io, err := net.IOCounters(false); err == nil && len(io) > 0 {
		values["net_bytes_sent"] = io[0].BytesSent
		values["net_bytes_recv"] = io[0].BytesRecv
		values["net_packets_sent"] = io[0].PacketsSent
		values["net_packets_recv"] = io[0].PacketsRecv
	}

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
}
