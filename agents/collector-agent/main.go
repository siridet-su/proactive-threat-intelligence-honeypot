package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nxadm/tail"
	"github.com/redis/go-redis/v9"
)

type LogSource struct {
	Name    string
	LogType string
	Path    string
	Stream  string
}

type AppConfig struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	SensorName    string
	LanIP         string
	LanInterface  string
	ZtIP          string
	ZtInterface   string
	ZeroTierIP    string
	ZeroTierIface string
	AllowedCIDRs  []*net.IPNet
	AllowedPorts  map[int]bool
	ReadFromStart bool
	StreamMaxLen  int64
}

func main() {
	cfg := loadConfig()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	ctx := context.Background()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	log.Printf("collector started")
	log.Printf("sensor=%s lan=%s zt=%s redis=%s", cfg.SensorName, cfg.LanIP, cfg.ZtIP, cfg.RedisAddr)

	sources := []LogSource{
		{
			Name:    "cowrie",
			LogType: "cowrie_json",
			Path:    getenv("COWRIE_LOG_FILE", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"),
			Stream:  "raw:cowrie",
		},
		{
			Name:    "zeek",
			LogType: "conn",
			Path:    getenv("ZEEK_CONN_LOG", "/usr/local/zeek/logs/current/conn.log"),
			Stream:  "raw:zeek:conn",
		},
		{
			Name:    "zeek",
			LogType: "ssh",
			Path:    getenv("ZEEK_SSH_LOG", "/usr/local/zeek/logs/current/ssh.log"),
			Stream:  "raw:zeek:ssh",
		},
		{
			Name:    "zeek",
			LogType: "ssl",
			Path:    getenv("ZEEK_SSL_LOG", "/usr/local/zeek/logs/current/ssl.log"),
			Stream:  "raw:zeek:ssl",
		},
		{Name: "zeek", LogType: "dns", Path: getenv("ZEEK_DNS_LOG", "/usr/local/zeek/logs/current/dns.log"), Stream: "raw:zeek:dns"},
		{Name: "zeek", LogType: "http", Path: getenv("ZEEK_HTTP_LOG", "/usr/local/zeek/logs/current/http.log"), Stream: "raw:zeek:http"},
		{Name: "zeek", LogType: "files", Path: getenv("ZEEK_FILES_LOG", "/usr/local/zeek/logs/current/files.log"), Stream: "raw:zeek:files"},
		{Name: "zeek", LogType: "notice", Path: getenv("ZEEK_NOTICE_LOG", "/usr/local/zeek/logs/current/notice.log"), Stream: "raw:zeek:notice"},
	}

	for _, src := range sources {
		go tailSource(ctx, rdb, cfg, src)
	}

	select {}
}

func loadConfig() AppConfig {
	redisDB, _ := strconv.Atoi(getenv("REDIS_DB", "0"))
	streamMaxLen, _ := strconv.ParseInt(getenv("RAW_STREAM_MAXLEN", "50000"), 10, 64)

	readFromStart := strings.EqualFold(getenv("READ_FROM_START", "false"), "true")

	return AppConfig{
		RedisAddr:     getenv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword: getenv("REDIS_PASSWORD", ""),
		RedisDB:       redisDB,

		SensorName:    getenv("SENSOR_NAME", "ubuntu-pi-server"),
		LanIP:         getenv("SENSOR_LAN_IP", "192.168.1.8"),
		LanInterface:  getenv("SENSOR_LAN_IFACE", "wlan0"),
		ZtIP:          getenv("SENSOR_ZT_IP", "10.123.100.42"),
		ZtInterface:   getenv("SENSOR_ZT_IFACE", "tailscale0"),
		ZeroTierIP:    getenv("SENSOR_ZEROTIER_IP", ""),
		ZeroTierIface: getenv("SENSOR_ZEROTIER_IFACE", ""),

		AllowedCIDRs:  parseCIDRs(getenv("ALLOW_CIDRS", "192.168.1.0/24,10.123.100.0/24")),
		AllowedPorts:  parsePorts(getenv("ALLOW_RESP_PORTS", "22,23,80,443,21,445")),
		ReadFromStart: readFromStart,
		StreamMaxLen:  streamMaxLen,
	}
}

func tailSource(ctx context.Context, rdb *redis.Client, cfg AppConfig, src LogSource) {
	for {
		if _, err := os.Stat(src.Path); err != nil {
			log.Printf("[%s/%s] waiting for file: %s", src.Name, src.LogType, src.Path)
			time.Sleep(30 * time.Second)
			continue
		}

		whence := os.SEEK_END
		if cfg.ReadFromStart {
			whence = os.SEEK_SET
		}

		t, err := tail.TailFile(src.Path, tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: false,
			Poll:      true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: whence,
			},
		})

		if err != nil {
			log.Printf("[%s/%s] tail error: %v", src.Name, src.LogType, err)
			time.Sleep(30 * time.Second)
			continue
		}

		log.Printf("[%s/%s] tailing %s -> %s", src.Name, src.LogType, src.Path, src.Stream)

		for line := range t.Lines {
			if line == nil {
				continue
			}

			text := strings.TrimSpace(line.Text)
			if text == "" {
				continue
			}

			var payload map[string]any
			if err := json.Unmarshal([]byte(text), &payload); err != nil {
				log.Printf("[%s/%s] invalid json: %v", src.Name, src.LogType, err)
				continue
			}

			keep, meta := shouldKeep(cfg, src, payload)
			if !keep {
				continue
			}

			dedupID := makeDedupID(src, payload, text)
			ingestedAt := time.Now().UTC().Format(time.RFC3339Nano)

			values := map[string]any{
				"source":      src.Name,
				"log_type":    src.LogType,
				"sensor_name": cfg.SensorName,
				"sensor_ip":   meta.SensorIP,
				"interface":   meta.Interface,
				"src_ip":      meta.SrcIP,
				"dst_ip":      meta.DstIP,
				"dst_port":    meta.DstPort,
				"dedup_id":    dedupID,
				"ingested_at": ingestedAt,
				"payload":     text,
			}

			id, err := rdb.XAdd(ctx, &redis.XAddArgs{
				Stream: src.Stream,
				MaxLen: cfg.StreamMaxLen,
				Approx: true,
				Values: values,
			}).Result()

			if err != nil {
				log.Printf("[%s/%s] redis xadd failed: %v", src.Name, src.LogType, err)
				continue
			}

			log.Printf("[%s/%s] kept id=%s iface=%s src=%s dst=%s:%s",
				src.Name,
				src.LogType,
				id,
				meta.Interface,
				meta.SrcIP,
				meta.DstIP,
				meta.DstPort,
			)
		}

		log.Printf("[%s/%s] tail stopped, restarting", src.Name, src.LogType)
		time.Sleep(2 * time.Second)
	}
}

type EventMeta struct {
	Interface string
	SensorIP  string
	SrcIP     string
	DstIP     string
	DstPort   string
}

func shouldKeep(cfg AppConfig, src LogSource, payload map[string]any) (bool, EventMeta) {
	switch src.Name {
	case "cowrie":
		return shouldKeepCowrie(cfg, payload)

	case "zeek":
		return shouldKeepZeek(cfg, payload)

	default:
		return false, EventMeta{}
	}
}

func shouldKeepCowrie(cfg AppConfig, payload map[string]any) (bool, EventMeta) {
	srcIP := getString(payload, "src_ip")
	if srcIP == "" {
		return false, EventMeta{}
	}

	dstIP := firstNonEmptyString(getString(payload, "dst_ip"), cfg.LanIP)
	dstPort := firstNonEmptyString(getString(payload, "dst_port"), "22")
	sensorIP := dstIP
	if net.ParseIP(sensorIP) == nil {
		sensorIP = cfg.LanIP
	}

	// Cowrie is authoritative for proxied destinations.
	return true, EventMeta{
		Interface: "honeypot",
		SensorIP:  sensorIP,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func shouldKeepZeek(cfg AppConfig, payload map[string]any) (bool, EventMeta) {
	origH := getString(payload, "id.orig_h")
	respH := getString(payload, "id.resp_h")
	respP := getInt(payload, "id.resp_p")

	if origH == "" || respH == "" || respP == 0 {
		return false, EventMeta{}
	}

	// รับเฉพาะ inbound service ที่ปลายทางคือ Pi ผ่าน LAN หรือ ZeroTier
	if respH != cfg.LanIP && respH != cfg.ZtIP && respH != cfg.ZeroTierIP {
		return false, EventMeta{}
	}

	// กันไม่ให้ admin SSH 2222 ปนเข้ามา และจำกัดเฉพาะ service ที่สนใจ
	if !cfg.AllowedPorts[respP] {
		return false, EventMeta{}
	}

	iface := ""
	switch respH {
	case cfg.LanIP:
		iface = cfg.LanInterface
	case cfg.ZtIP:
		iface = cfg.ZtInterface
	case cfg.ZeroTierIP:
		iface = cfg.ZeroTierIface
	}

	if iface == "" {
		return false, EventMeta{}
	}

	return true, EventMeta{
		Interface: iface,
		SensorIP:  respH,
		SrcIP:     origH,
		DstIP:     respH,
		DstPort:   strconv.Itoa(respP),
	}
}

func inferInterfaceFromPeer(cfg AppConfig, peerIP string) (string, string) {
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return "", ""
	}

	_, lanNet, _ := net.ParseCIDR("192.168.1.0/24")
	_, ztNet, _ := net.ParseCIDR("10.123.100.0/24")

	if lanNet.Contains(ip) {
		return cfg.LanInterface, cfg.LanIP
	}

	if ztNet.Contains(ip) {
		return cfg.ZtInterface, cfg.ZtIP
	}

	return "", ""
}

func makeDedupID(src LogSource, payload map[string]any, raw string) string {
	parts := []string{
		src.Name,
		src.LogType,
		getString(payload, "timestamp"),
		getString(payload, "ts"),
		getString(payload, "uid"),
		getString(payload, "session"),
		getString(payload, "eventid"),
		getString(payload, "id.orig_h"),
		fmt.Sprint(getAny(payload, "id.orig_p")),
		getString(payload, "id.resp_h"),
		fmt.Sprint(getAny(payload, "id.resp_p")),
		raw,
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}

	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		return fmt.Sprint(t)
	}
}

func getInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}

	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func getAny(m map[string]any, key string) any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	return v
}

func parseCIDRs(raw string) []*net.IPNet {
	var result []*net.IPNet

	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		_, cidr, err := net.ParseCIDR(item)
		if err != nil {
			log.Printf("invalid cidr ignored: %s", item)
			continue
		}

		result = append(result, cidr)
	}

	return result
}

func ipInAllowedCIDRs(ipText string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return false
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func parsePorts(raw string) map[int]bool {
	result := make(map[int]bool)

	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		port, err := strconv.Atoi(item)
		if err != nil {
			log.Printf("invalid port ignored: %s", item)
			continue
		}

		result[port] = true
	}

	return result
}

func getenv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
