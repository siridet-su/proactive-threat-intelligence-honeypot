package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var rawStreams = []string{
	"raw:hardware",
	"raw:cowrie",
	"raw:zeek:conn",
	"raw:zeek:ssh",
	"raw:zeek:ssl",
	"raw:zeek:dns",
	"raw:zeek:http",
	"raw:zeek:files",
	"raw:zeek:notice",
}

type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	GroupName    string
	ConsumerName string

	LookupDir string

	MongoURI string
	MongoDB  string

	TIEnabled    bool
	TIJobsStream string
	TIJobsMaxLen int64
}

type LookupRecord struct {
	Application string   `json:"application"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Confidence  int      `json:"confidence"`
	Tags        []string `json:"tags"`
}

type LookupStore struct {
	HASSH     map[string]LookupRecord
	JA3       map[string]LookupRecord
	JA3S      map[string]LookupRecord
	SSHBanner map[string]LookupRecord
	SNIRules  map[string]LookupRecord
}

type MongoWriter struct {
	enabled bool
	db      *mongo.Database
}

func main() {
	// โหลดไฟล์ .env
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ No .env file found or unable to load, using system env variables")
	}

	cfg := loadConfig()
	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	lookups := loadLookups(cfg.LookupDir)

	mw, err := newMongoWriter(ctx, cfg)
	if err != nil {
		log.Fatalf("mongo init failed: %v", err)
	}

	for _, stream := range rawStreams {
		ensureConsumerGroup(ctx, rdb, stream, cfg.GroupName)
	}

	log.Printf(
		"processor started redis=%s group=%s consumer=%s lookup_dir=%s mongo_enabled=%v",
		cfg.RedisAddr,
		cfg.GroupName,
		cfg.ConsumerName,
		cfg.LookupDir,
		mw.enabled,
	)

	go recoverPendingLoop(ctx, rdb, mw, lookups, cfg)
	processLoop(ctx, rdb, mw, lookups, cfg)
}

func loadConfig() Config {
	redisDB, _ := strconv.Atoi(getenv("REDIS_DB", "0"))
	tiJobsMaxLen, _ := strconv.ParseInt(getenv("TI_JOBS_STREAM_MAXLEN", "50000"), 10, 64)

	return Config{
		RedisAddr:     getenv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword: getenv("REDIS_PASSWORD", ""),
		RedisDB:       redisDB,

		GroupName:    getenv("CONSUMER_GROUP", "processor"),
		ConsumerName: getenv("CONSUMER_NAME", "processor-1"),

		LookupDir: getenv("LOOKUP_DIR", "/home/cpe27/honeypot-pipeline/lookups"),

		MongoURI: getenv("MONGO_URI", ""),
		MongoDB:  getenv("MONGO_DATABASE", "honeypot"),

		TIEnabled:    strings.EqualFold(getenv("THREAT_INTEL_ENABLED", "false"), "true"),
		TIJobsStream: getenv("TI_JOBS_STREAM", "ti:jobs"),
		TIJobsMaxLen: tiJobsMaxLen,
	}
}

func processLoop(ctx context.Context, rdb *redis.Client, mw *MongoWriter, lookups LookupStore, cfg Config) {
	streamArgs := make([]string, 0, len(rawStreams)*2)

	for _, stream := range rawStreams {
		streamArgs = append(streamArgs, stream)
	}

	for range rawStreams {
		streamArgs = append(streamArgs, ">")
	}

	for {
		res, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    cfg.GroupName,
			Consumer: cfg.ConsumerName,
			Streams:  streamArgs,
			Count:    20,
			Block:    5 * time.Second,
		}).Result()

		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}

			log.Printf("xreadgroup error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		for _, stream := range res {
			for _, msg := range stream.Messages {
				if err := processMessage(ctx, rdb, mw, lookups, cfg, stream.Stream, msg); err != nil {
					log.Printf("process failed stream=%s id=%s err=%v", stream.Stream, msg.ID, err)
					continue
				}

				if err := rdb.XAck(ctx, stream.Stream, cfg.GroupName, msg.ID).Err(); err != nil {
					log.Printf("xack failed stream=%s id=%s err=%v", stream.Stream, msg.ID, err)
				}
			}
		}
	}
}

func recoverPendingLoop(ctx context.Context, rdb *redis.Client, mw *MongoWriter, lookups LookupStore, cfg Config) {
	for {
		for _, stream := range rawStreams {
			messages, _, err := rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{
				Stream: stream, Group: cfg.GroupName, Consumer: cfg.ConsumerName,
				MinIdle: 30 * time.Second, Start: "0-0", Count: 100,
			}).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				log.Printf("xautoclaim failed stream=%s err=%v", stream, err)
				continue
			}
			for _, msg := range messages {
				if err := processMessage(ctx, rdb, mw, lookups, cfg, stream, msg); err != nil {
					log.Printf("pending retry failed stream=%s id=%s err=%v", stream, msg.ID, err)
					continue
				}
				if err := rdb.XAck(ctx, stream, cfg.GroupName, msg.ID).Err(); err != nil {
					log.Printf("pending xack failed stream=%s id=%s err=%v", stream, msg.ID, err)
				}
			}
		}
		time.Sleep(time.Minute)
	}
}

func processMessage(
	ctx context.Context,
	rdb *redis.Client,
	mw *MongoWriter,
	lookups LookupStore,
	cfg Config,
	streamName string,
	msg redis.XMessage,
) error {
	if streamName == "raw:hardware" {
		doc := map[string]interface{}{}
		for k, v := range msg.Values {
			strVal := valueToString(v)
			if f, err := strconv.ParseFloat(strVal, 64); err == nil {
				doc[k] = f
			} else {
				doc[k] = strVal
			}
		}
		// Convert Unix timestamp to MongoDB DateTime if present
		if ts, ok := doc["timestamp"].(float64); ok {
			doc["timestamp"] = time.Unix(int64(ts), 0)
		}
		_, err := mw.db.Collection("hardware_metrics").InsertOne(ctx, doc)
		return err
	}

	source := valueToString(msg.Values["source"])
	logType := valueToString(msg.Values["log_type"])
	payloadText := valueToString(msg.Values["payload"])

	if payloadText == "" {
		return fmt.Errorf("empty payload")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
		return fmt.Errorf("invalid payload json: %w", err)
	}

	normalized := normalizeEvent(streamName, msg.ID, msg.Values, payload)
	enriched := enrichEvent(normalized, lookups)

	srcIP := getNestedString(enriched, "network.src_ip")
	eventJSON := mustJSON(enriched)

	eventID := getNestedString(enriched, "event_id")
	eventType := getNestedString(enriched, "event_type")
	dstIP := getNestedString(enriched, "network.dst_ip")
	dstPort := getNestedString(enriched, "network.dst_port")

	// MongoDB is the durable sink. Only acknowledge the raw message after this
	// idempotent upsert succeeds. This gives the pipeline at-least-once delivery
	// without duplicate documents.
	if err := mw.upsertEvent(ctx, enriched); err != nil {
		return fmt.Errorf("mongo upsert event failed: %w", err)
	}

	// Threat-intelligence calls must not delay or block ingestion. The worker
	// receives one idempotent job per supported observable after MongoDB has the
	// canonical event, and attaches its result later.
	if err := enqueueThreatIntelJobs(ctx, rdb, cfg, source, eventID, eventType, srcIP, payload); err != nil {
		return fmt.Errorf("enqueue threat-intelligence jobs: %w", err)
	}

	if _, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: "event:canonical",
		MaxLen: 50000,
		Approx: true,
		Values: map[string]any{
			"event_id": eventID, "source": source, "log_type": logType,
			"event_type": eventType, "src_ip": srcIP, "dst_ip": dstIP,
			"dst_port": dstPort, "event_json": eventJSON,
		},
	}).Result(); err != nil {
		return fmt.Errorf("xadd canonical failed: %w", err)
	}

	cacheLookups(ctx, rdb, enriched)

	log.Printf(
		"enriched stream=%s id=%s type=%s src=%s dst=%s:%s",
		streamName,
		msg.ID,
		eventType,
		srcIP,
		dstIP,
		dstPort,
	)

	return nil
}

func normalizeEvent(streamName string, rawID string, values map[string]any, payload map[string]any) map[string]any {
	source := valueToString(values["source"])
	logType := valueToString(values["log_type"])

	srcIP := firstNonEmpty(
		getPayloadString(payload, "id.orig_h"),
		valueToString(values["src_ip"]),
		getPayloadString(payload, "src_ip"),
	)

	srcPort := anyToString(getPayloadAny(payload, "id.orig_p"))

	dstIP := firstNonEmpty(
		getPayloadString(payload, "id.resp_h"),
		valueToString(values["dst_ip"]),
		valueToString(values["sensor_ip"]),
	)

	dstPort := firstNonEmpty(
		anyToString(getPayloadAny(payload, "id.resp_p")),
		valueToString(values["dst_port"]),
	)

	protocol := getPayloadString(payload, "proto")
	service := getPayloadString(payload, "service")

	if source == "cowrie" {
		if dstPort == "" {
			dstPort = "22"
		}
		if protocol == "" {
			protocol = "tcp"
		}
		if service == "" {
			service = "ssh"
		}
	}

	if source == "zeek" {
		if protocol == "" {
			protocol = "tcp"
		}

		switch logType {
		case "ssh":
			if service == "" {
				service = "ssh"
			}
		case "ssl":
			if service == "" {
				service = "ssl"
			}
		}
	}

	sshVersion := ""
	tlsVersion := ""
	tlsCipher := ""

	if source == "zeek" && logType == "ssh" {
		sshVersion = getPayloadString(payload, "version")
	}

	if source == "zeek" && logType == "ssl" {
		tlsVersion = getPayloadString(payload, "version")
		tlsCipher = getPayloadString(payload, "cipher")
	}

	identity := map[string]any{
		"username": "",
		"password": "",
	}

	activity := map[string]any{
		"command":  "",
		"message":  "",
		"eventid":  "",
		"ttylog":   "",
		"filename": "",
	}

	cowrie := map[string]any{
		"session":  "",
		"eventid":  "",
		"duration": "",
	}

	zeek := map[string]any{
		"uid":           "",
		"conn_state":    "",
		"orig_bytes":    nil,
		"resp_bytes":    nil,
		"orig_pkts":     nil,
		"resp_pkts":     nil,
		"auth_success":  nil,
		"auth_attempts": nil,
	}

	if source == "cowrie" {
		identity["username"] = getPayloadString(payload, "username")
		identity["password"] = getPayloadString(payload, "password")

		activity["command"] = getPayloadString(payload, "input")
		activity["message"] = getPayloadString(payload, "message")
		activity["eventid"] = getPayloadString(payload, "eventid")
		activity["ttylog"] = getPayloadString(payload, "ttylog")
		activity["filename"] = getPayloadString(payload, "filename")

		cowrie["session"] = getPayloadString(payload, "session")
		cowrie["eventid"] = getPayloadString(payload, "eventid")
		cowrie["duration"] = getPayloadString(payload, "duration")
	}

	if source == "zeek" {
		zeek["uid"] = getPayloadString(payload, "uid")
		zeek["conn_state"] = getPayloadString(payload, "conn_state")
		zeek["orig_bytes"] = getPayloadAny(payload, "orig_bytes")
		zeek["resp_bytes"] = getPayloadAny(payload, "resp_bytes")
		zeek["orig_pkts"] = getPayloadAny(payload, "orig_pkts")
		zeek["resp_pkts"] = getPayloadAny(payload, "resp_pkts")
		zeek["auth_success"] = getPayloadAny(payload, "auth_success")
		zeek["auth_attempts"] = getPayloadAny(payload, "auth_attempts")
	}

	dedupID := valueToString(values["dedup_id"])
	if dedupID == "" {
		dedupID = makeEventID(streamName, mustJSON(payload))
	}

	event := map[string]any{
		"event_id":    dedupID,
		"timestamp":   normalizeTimestamp(payload),
		"ingested_at": valueToString(values["ingested_at"]),
		"source":      source,
		"log_type":    logType,
		"event_type":  inferEventType(source, logType, payload),

		"sensor": map[string]any{
			"name":      valueToString(values["sensor_name"]),
			"ip":        valueToString(values["sensor_ip"]),
			"interface": valueToString(values["interface"]),
		},

		"network": map[string]any{
			"src_ip":   srcIP,
			"src_port": portValue(srcPort),
			"dst_ip":   dstIP,
			"dst_port": portValue(dstPort),
			"protocol": protocol,
			"service":  service,
		},

		"identity": identity,
		"activity": activity,

		"fingerprints": map[string]any{
			"ssh_client":         getPayloadString(payload, "client"),
			"ssh_server":         getPayloadString(payload, "server"),
			"ssh_version":        sshVersion,
			"hassh":              getPayloadString(payload, "hassh"),
			"hassh_server":       getPayloadString(payload, "hasshServer"),
			"hassh_algorithms":   getPayloadString(payload, "hasshAlgorithms"),
			"hassh_server_algos": getPayloadString(payload, "hasshServerAlgorithms"),

			"ja3":         getPayloadString(payload, "ja3"),
			"ja3s":        getPayloadString(payload, "ja3s"),
			"sni":         getPayloadString(payload, "server_name"),
			"tls_version": tlsVersion,
			"tls_cipher":  tlsCipher,
		},

		"zeek":    zeek,
		"cowrie":  cowrie,
		"session": map[string]any{"id": firstNonEmpty(getPayloadString(payload, "session"), getPayloadString(payload, "uid")), "source": source},

		"raw": map[string]any{
			"redis_stream": streamName,
			"redis_id":     rawID,
			"dedup_id":     valueToString(values["dedup_id"]),
			"payload":      payload,
		},
	}

	return compactMap(event)
}

func enrichEvent(event map[string]any, lookups LookupStore) map[string]any {
	enriched := deepCopy(event)

	matches := make([]map[string]any, 0)
	allTags := map[string]bool{}

	maxConfidence := 0
	primaryApplication := ""
	primaryCategory := "unknown"

	addMatch := func(kind string, value string, rec LookupRecord) {
		if value == "" {
			return
		}

		app := rec.Application
		if app == "" {
			app = rec.Name
		}
		if app == "" {
			app = "Unknown"
		}

		match := map[string]any{
			"type":        kind,
			"value":       value,
			"application": app,
			"category":    rec.Category,
			"confidence":  rec.Confidence,
			"tags":        rec.Tags,
		}

		matches = append(matches, match)

		if rec.Confidence > maxConfidence {
			maxConfidence = rec.Confidence
			primaryApplication = app
			primaryCategory = rec.Category
		}

		for _, tag := range rec.Tags {
			allTags[tag] = true
		}
	}

	hassh := getNestedString(enriched, "fingerprints.hassh")
	hasshServer := getNestedString(enriched, "fingerprints.hassh_server")
	ja3 := getNestedString(enriched, "fingerprints.ja3")
	ja3s := getNestedString(enriched, "fingerprints.ja3s")
	sshClient := getNestedString(enriched, "fingerprints.ssh_client")
	sshServer := getNestedString(enriched, "fingerprints.ssh_server")
	sni := getNestedString(enriched, "fingerprints.sni")

	if rec, ok := lookups.HASSH[hassh]; ok {
		addMatch("hassh", hassh, rec)
	}
	if rec, ok := lookups.HASSH[hasshServer]; ok {
		addMatch("hassh_server", hasshServer, rec)
	}
	if rec, ok := lookups.JA3[ja3]; ok {
		addMatch("ja3", ja3, rec)
	}
	if rec, ok := lookups.JA3S[ja3s]; ok {
		addMatch("ja3s", ja3s, rec)
	}
	if rec, ok := lookups.SSHBanner[sshClient]; ok {
		addMatch("ssh_client_banner", sshClient, rec)
	}
	if rec, ok := lookups.SSHBanner[sshServer]; ok {
		addMatch("ssh_server_banner", sshServer, rec)
	}

	for pattern, rec := range lookups.SNIRules {
		if sni != "" && strings.Contains(strings.ToLower(sni), strings.ToLower(pattern)) {
			addMatch("sni", sni, rec)
		}
	}

	if len(matches) == 0 {
		if strings.Contains(strings.ToLower(sshClient), "openssh") {
			addMatch("heuristic", sshClient, LookupRecord{
				Application: "OpenSSH Client",
				Category:    "ssh_client",
				Confidence:  60,
				Tags:        []string{"openssh", "heuristic"},
			})
		} else if ja3 != "" {
			addMatch("heuristic", ja3, LookupRecord{
				Application: "Unknown TLS Client",
				Category:    "tls_client_unknown",
				Confidence:  30,
				Tags:        []string{"tls", "unknown-ja3"},
			})
		}
	}

	clientEnrichment := buildSideEnrichment(matches, []string{
		"hassh",
		"ssh_client_banner",
		"ja3",
		"sni",
		"heuristic",
	})

	serverEnrichment := buildSideEnrichment(matches, []string{
		"hassh_server",
		"ssh_server_banner",
		"ja3s",
	})

	riskScore := computeRiskScore(enriched, clientEnrichment, serverEnrichment, matches)

	tagList := mapKeysToSlice(allTags)

	summary := primaryApplication
	clientApp := valueToString(clientEnrichment["application"])
	serverApp := valueToString(serverEnrichment["application"])

	if clientApp != "" && serverApp != "" {
		summary = fmt.Sprintf("%s -> %s", clientApp, serverApp)
	} else if clientApp != "" {
		summary = clientApp
	} else if serverApp != "" {
		summary = serverApp
	}

	enrichedAt := time.Now().UTC().Format(time.RFC3339Nano)

	enriched["enrichment"] = map[string]any{
		"summary":     summary,
		"application": primaryApplication,
		"category":    primaryCategory,
		"confidence":  maxConfidence,
		"risk_score":  riskScore,
		"tags":        tagList,
		"matches":     matches,
		"enriched_at": enrichedAt,
	}

	if valueToString(clientEnrichment["application"]) != "" {
		enriched["client_enrichment"] = clientEnrichment
	}
	if valueToString(serverEnrichment["application"]) != "" {
		enriched["server_enrichment"] = serverEnrichment
	}

	return compactMap(enriched)
}

func buildSideEnrichment(matches []map[string]any, allowedTypes []string) map[string]any {
	allowed := map[string]bool{}
	for _, t := range allowedTypes {
		allowed[t] = true
	}

	bestConfidence := -1
	bestApplication := ""
	bestCategory := ""
	matchedBy := make([]string, 0)
	sideMatches := make([]map[string]any, 0)
	tags := map[string]bool{}

	for _, m := range matches {
		matchType := valueToString(m["type"])
		if !allowed[matchType] {
			continue
		}

		conf := anyToInt(m["confidence"])

		if conf > bestConfidence {
			bestConfidence = conf
			bestApplication = valueToString(m["application"])
			bestCategory = valueToString(m["category"])
		}

		matchedBy = append(matchedBy, matchType)
		sideMatches = append(sideMatches, m)

		for _, tag := range anyToStringSlice(m["tags"]) {
			tags[tag] = true
		}
	}

	if bestConfidence < 0 {
		bestConfidence = 0
	}

	return map[string]any{
		"application": bestApplication,
		"category":    bestCategory,
		"confidence":  bestConfidence,
		"matched_by":  matchedBy,
		"tags":        mapKeysToSlice(tags),
		"matches":     sideMatches,
	}
}

func computeRiskScore(
	event map[string]any,
	clientEnrichment map[string]any,
	serverEnrichment map[string]any,
	matches []map[string]any,
) int {
	score := 10

	eventType := getNestedString(event, "event_type")
	srcIP := getNestedString(event, "network.src_ip")
	dstPort := getNestedString(event, "network.dst_port")
	clientCategory := valueToString(clientEnrichment["category"])

	switch eventType {
	case "ssh_login_success":
		score += 40
	case "ssh_login_failed":
		score += 25
	case "ssh_command":
		score += 35
	case "ssh_fingerprint":
		score += 15
	case "tls_fingerprint":
		score += 10
	case "network_connection":
		score += 5
	}

	switch dstPort {
	case "22":
		score += 10
	case "23":
		score += 15
	case "443":
		score += 5
	case "3306":
		score += 15
	}

	if !isLocalLabIP(srcIP) {
		score += 25
	}

	if strings.Contains(clientCategory, "unknown") {
		score += 15
	}
	if strings.Contains(clientCategory, "scanner") {
		score += 30
	}
	if strings.Contains(clientCategory, "malware") {
		score += 50
	}
	if strings.Contains(clientCategory, "infrastructure_traffic") {
		score -= 10
	}

	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}

	return score
}

func inferEventType(source string, logType string, payload map[string]any) string {
	if source == "cowrie" {
		eventID := getPayloadString(payload, "eventid")

		switch eventID {
		case "cowrie.login.success":
			return "ssh_login_success"
		case "cowrie.login.failed":
			return "ssh_login_failed"
		case "cowrie.command.input":
			return "ssh_command"
		case "cowrie.client.kex":
			return "ssh_fingerprint"
		case "cowrie.session.connect":
			return "session_connect"
		case "cowrie.session.closed":
			return "session_closed"
		default:
			if eventID != "" {
				return eventID
			}
			return "cowrie_event"
		}
	}

	if source == "zeek" {
		switch logType {
		case "conn":
			return "network_connection"
		case "ssh":
			return "ssh_fingerprint"
		case "ssl":
			return "tls_fingerprint"
		case "dns":
			return "dns_query"
		case "http":
			return "http_request"
		case "files":
			return "file_observed"
		case "notice":
			return "security_notice"
		}
	}

	return "unknown"
}

func cacheLookups(ctx context.Context, rdb *redis.Client, event map[string]any) {
	enrichment, ok := event["enrichment"].(map[string]any)
	if !ok {
		return
	}

	matches, ok := enrichment["matches"].([]map[string]any)
	if !ok {
		return
	}

	for _, m := range matches {
		matchType := valueToString(m["type"])
		value := valueToString(m["value"])

		if matchType == "" || value == "" {
			continue
		}

		key := fmt.Sprintf("cache:lookup:%s:%s", matchType, value)
		_ = rdb.Set(ctx, key, mustJSON(m), 24*time.Hour).Err()
	}
}

func ensureConsumerGroup(ctx context.Context, rdb *redis.Client, stream string, group string) {
	err := rdb.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		log.Fatalf("failed to create group stream=%s group=%s err=%v", stream, group, err)
	}
}

func newMongoWriter(ctx context.Context, cfg Config) (*MongoWriter, error) {
	if cfg.MongoURI == "" {
		return &MongoWriter{enabled: false}, nil
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	mw := &MongoWriter{enabled: true, db: client.Database(cfg.MongoDB)}
	if err := mw.ensureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("ensure mongo indexes: %w", err)
	}
	return mw, nil
}

func (mw *MongoWriter) upsertEvent(ctx context.Context, doc map[string]any) error {
	if !mw.enabled {
		return fmt.Errorf("MongoDB is disabled; refusing to acknowledge durable event")
	}
	eventID := getNestedString(doc, "event_id")
	if eventID == "" {
		return fmt.Errorf("event_id is empty")
	}
	_, err := mw.db.Collection("events").UpdateOne(
		ctx, bson.M{"_id": eventID}, bson.M{"$setOnInsert": doc},
		options.Update().SetUpsert(true),
	)
	return err
}

func (mw *MongoWriter) ensureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "source", Value: 1}, {Key: "event_type", Value: 1}, {Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "network.src_ip", Value: 1}, {Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "session.id", Value: 1}, {Key: "timestamp", Value: 1}}, Options: options.Index().SetSparse(true)},
	}
	_, err := mw.db.Collection("events").Indexes().CreateMany(ctx, indexes)
	return err
}

func loadLookups(dir string) LookupStore {
	return LookupStore{
		HASSH:     loadLookupFile(filepath.Join(dir, "hassh_clients.json")),
		JA3:       loadLookupFile(filepath.Join(dir, "ja3_fingerprints.json")),
		JA3S:      loadLookupFile(filepath.Join(dir, "ja3s_fingerprints.json")),
		SSHBanner: loadLookupFile(filepath.Join(dir, "ssh_banners.json")),
		SNIRules:  loadLookupFile(filepath.Join(dir, "sni_rules.json")),
	}
}

func loadLookupFile(path string) map[string]LookupRecord {
	result := map[string]LookupRecord{}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("lookup file skipped: %s", path)
		return result
	}

	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("lookup file invalid: %s err=%v", path, err)
		return map[string]LookupRecord{}
	}

	log.Printf("loaded lookup %s count=%d", path, len(result))
	return result
}

func normalizeTimestamp(payload map[string]any) time.Time {
	if ts := getPayloadString(payload, "timestamp"); ts != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return parsed.UTC()
		}
	}

	v := getPayloadAny(payload, "ts")

	switch t := v.(type) {
	case float64:
		sec := int64(t)
		nsec := int64((t - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC()

	case int64:
		return time.Unix(t, 0).UTC()

	case int:
		return time.Unix(int64(t), 0).UTC()

	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err == nil {
			sec := int64(f)
			nsec := int64((f - float64(sec)) * 1e9)
			return time.Unix(sec, nsec).UTC()
		}
	}

	return time.Now().UTC()
}

func makeEventID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func getPayloadString(m map[string]any, key string) string {
	return valueToString(getPayloadAny(m, key))
}

func getPayloadAny(m map[string]any, key string) any {
	v, ok := m[key]
	if !ok {
		return nil
	}

	return v
}

func getNestedString(m map[string]any, path string) string {
	parts := strings.Split(path, ".")
	var current any = m

	for _, part := range parts {
		asMap, ok := current.(map[string]any)
		if !ok {
			return ""
		}

		current = asMap[part]
	}

	return valueToString(current)
}

func valueToString(v any) string {
	if v == nil {
		return ""
	}

	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(t)
	}
}

func anyToString(v any) string {
	return valueToString(v)
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func anyToStringSlice(v any) []string {
	result := []string{}

	switch t := v.(type) {
	case []string:
		return t

	case []any:
		for _, item := range t {
			result = append(result, valueToString(item))
		}
	}

	return result
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}

	return ""
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}

	return string(data)
}

func deepCopy(in map[string]any) map[string]any {
	var out map[string]any
	_ = json.Unmarshal([]byte(mustJSON(in)), &out)
	return out
}

func mapKeysToSlice(m map[string]bool) []string {
	result := make([]string, 0, len(m))

	for k := range m {
		result = append(result, k)
	}

	return result
}

func isLocalLabIP(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "100.64.") ||
		strings.HasPrefix(ip, "127.")
}

func portValue(value string) any {
	if value == "" {
		return nil
	}
	if port, err := strconv.Atoi(value); err == nil {
		return port
	}
	return value
}

func compactMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			child := compactMap(typed)
			if len(child) > 0 {
				result[key] = child
			}
		case string:
			if strings.TrimSpace(typed) != "" {
				result[key] = typed
			}
		case []string:
			if len(typed) > 0 {
				result[key] = typed
			}
		case []map[string]any:
			if len(typed) > 0 {
				result[key] = typed
			}
		case []any:
			if len(typed) > 0 {
				result[key] = typed
			}
		case nil:
			continue
		default:
			result[key] = value
		}
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
