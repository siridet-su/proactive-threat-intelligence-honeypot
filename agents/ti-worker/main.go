// ti-worker enriches observables after the event pipeline has persisted them.
// It never executes a downloaded file and only asks VirusTotal about a SHA-256
// hash that Cowrie or Zeek already recorded.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	jobStream         = "ti:jobs"
	defaultCacheTTL   = 7 * 24 * time.Hour
	skippedCacheTTL   = time.Hour
	providerBodyLimit = 1 << 20
)

type config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	JobsStream    string
	Group         string
	Consumer      string

	MongoURI string
	MongoDB  string

	VirusTotalKey string
	AbuseIPDBKey  string
	HTTPTimeout   time.Duration
	CacheTTL      time.Duration

	VTPerMinute    int
	VTPerDay       int
	AbusePerMinute int
	AbusePerDay    int
}

type threatIntelJob struct {
	JobID          string `json:"job_id"`
	Provider       string `json:"provider"`
	ObservableType string `json:"observable_type"`
	Observable     string `json:"observable"`
	SourceEventID  string `json:"source_event_id"`
	SessionID      string `json:"session_id,omitempty"`
	Priority       string `json:"priority"`
	RequestedAt    string `json:"requested_at"`
	SchemaVersion  string `json:"schema_version"`
}

type enrichmentRecord struct {
	ID             string         `bson:"_id" json:"id"`
	Provider       string         `bson:"provider" json:"provider"`
	ObservableType string         `bson:"observable_type" json:"observable_type"`
	Observable     string         `bson:"observable" json:"observable"`
	Status         string         `bson:"status" json:"status"`
	Summary        map[string]any `bson:"summary" json:"summary"`
	QueriedAt      time.Time      `bson:"queried_at" json:"queried_at"`
	ExpiresAt      time.Time      `bson:"expires_at" json:"expires_at"`
}

type worker struct {
	cfg    config
	redis  *redis.Client
	mongo  *mongo.Database
	client *http.Client
}

type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

func main() {
	cfg := loadConfig()
	if cfg.MongoURI == "" {
		log.Fatal("MONGO_URI is required; refusing to acknowledge threat-intelligence jobs without a durable result store")
	}

	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		log.Fatalf("mongo connect failed: %v", err)
	}
	defer func() { _ = mongoClient.Disconnect(context.Background()) }()

	w := &worker{
		cfg:    cfg,
		redis:  rdb,
		mongo:  mongoClient.Database(cfg.MongoDB),
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}
	if err := w.ensureIndexes(ctx); err != nil {
		log.Fatalf("create MongoDB indexes: %v", err)
	}
	if err := ensureGroup(ctx, rdb, cfg.JobsStream, cfg.Group); err != nil {
		log.Fatalf("create Redis consumer group: %v", err)
	}

	log.Printf("ti-worker started redis=%s stream=%s group=%s consumer=%s cache_ttl=%s", cfg.RedisAddr, cfg.JobsStream, cfg.Group, cfg.Consumer, cfg.CacheTTL)
	go w.recoverPending(ctx)
	w.consume(ctx)
}

func loadConfig() config {
	return config{
		RedisAddr:      getenv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:  getenv("REDIS_PASSWORD", ""),
		RedisDB:        getenvInt("REDIS_DB", 0),
		JobsStream:     getenv("TI_JOBS_STREAM", jobStream),
		Group:          getenv("TI_CONSUMER_GROUP", "ti-worker"),
		Consumer:       getenv("TI_CONSUMER_NAME", hostnameOr("ti-worker-1")),
		MongoURI:       getenv("MONGO_URI", ""),
		MongoDB:        getenv("MONGO_DATABASE", "honeypot_db"),
		VirusTotalKey:  strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY")),
		AbuseIPDBKey:   strings.TrimSpace(os.Getenv("ABUSEIPDB_API_KEY")),
		HTTPTimeout:    getenvDuration("TI_HTTP_TIMEOUT", 8*time.Second),
		CacheTTL:       getenvDuration("TI_CACHE_TTL", defaultCacheTTL),
		VTPerMinute:    getenvInt("VT_MAX_REQUESTS_PER_MINUTE", 2),
		VTPerDay:       getenvInt("VT_MAX_REQUESTS_PER_DAY", 200),
		AbusePerMinute: getenvInt("ABUSEIPDB_MAX_REQUESTS_PER_MINUTE", 2),
		AbusePerDay:    getenvInt("ABUSEIPDB_MAX_REQUESTS_PER_DAY", 200),
	}
}

func (w *worker) consume(ctx context.Context) {
	for {
		streams, err := w.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group: w.cfg.Group, Consumer: w.cfg.Consumer,
			Streams: []string{w.cfg.JobsStream, ">"}, Count: 10, Block: 5 * time.Second,
		}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			log.Printf("xreadgroup error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, stream := range streams {
			for _, message := range stream.Messages {
				w.handleMessage(ctx, stream.Stream, message)
			}
		}
	}
}

func (w *worker) recoverPending(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		messages, _, err := w.redis.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream: w.cfg.JobsStream, Group: w.cfg.Group, Consumer: w.cfg.Consumer,
			MinIdle: time.Minute, Start: "0-0", Count: 100,
		}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			log.Printf("xautoclaim error: %v", err)
			continue
		}
		for _, message := range messages {
			w.handleMessage(ctx, w.cfg.JobsStream, message)
		}
	}
}

func (w *worker) handleMessage(ctx context.Context, stream string, message redis.XMessage) {
	job, err := decodeJob(message)
	if err != nil {
		log.Printf("invalid job id=%s: %v; acknowledging", message.ID, err)
		w.ack(ctx, stream, message.ID)
		return
	}
	if err := w.processJob(ctx, job); err != nil {
		var retry retryableError
		if errors.As(err, &retry) {
			log.Printf("retryable job failure job=%s provider=%s: %v", job.JobID, job.Provider, err)
			return
		}
		log.Printf("permanent job failure job=%s provider=%s: %v; acknowledging", job.JobID, job.Provider, err)
		w.ack(ctx, stream, message.ID)
		return
	}
	w.ack(ctx, stream, message.ID)
}

func (w *worker) processJob(ctx context.Context, job threatIntelJob) error {
	if err := validateJob(job); err != nil {
		return err
	}

	record, found, err := w.lookupCached(ctx, job)
	if err != nil {
		return retryableError{err}
	}
	if !found {
		record, err = w.queryProvider(ctx, job)
		if err != nil {
			return err
		}
		if err := w.storeRecord(ctx, record); err != nil {
			return retryableError{fmt.Errorf("store result: %w", err)}
		}
	}

	if err := w.attachToEvent(ctx, job, record); err != nil {
		return retryableError{fmt.Errorf("attach result to event: %w", err)}
	}
	return nil
}

func (w *worker) lookupCached(ctx context.Context, job threatIntelJob) (enrichmentRecord, bool, error) {
	var record enrichmentRecord
	cacheKey := "ti:cache:" + job.JobID
	if raw, err := w.redis.Get(ctx, cacheKey).Result(); err == nil {
		if err := json.Unmarshal([]byte(raw), &record); err == nil && record.ExpiresAt.After(time.Now().UTC()) {
			return record, true, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		return record, false, fmt.Errorf("read Redis cache: %w", err)
	}

	err := w.mongo.Collection("threat_intel").FindOne(ctx, bson.M{"_id": job.JobID, "expires_at": bson.M{"$gt": time.Now().UTC()}}).Decode(&record)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return enrichmentRecord{}, false, nil
	}
	if err != nil {
		return enrichmentRecord{}, false, fmt.Errorf("read MongoDB cache: %w", err)
	}
	if raw, err := json.Marshal(record); err == nil {
		_ = w.redis.Set(ctx, cacheKey, raw, time.Until(record.ExpiresAt)).Err()
	}
	return record, true, nil
}

func (w *worker) storeRecord(ctx context.Context, record enrichmentRecord) error {
	_, err := w.mongo.Collection("threat_intel").UpdateOne(
		ctx, bson.M{"_id": record.ID}, bson.M{"$set": record}, options.Update().SetUpsert(true),
	)
	if err != nil {
		return err
	}
	if raw, err := json.Marshal(record); err == nil {
		if err := w.redis.Set(ctx, "ti:cache:"+record.ID, raw, time.Until(record.ExpiresAt)).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (w *worker) attachToEvent(ctx context.Context, job threatIntelJob, record enrichmentRecord) error {
	if job.SourceEventID == "" {
		return nil
	}
	field := "threat_intel." + record.Provider
	value := bson.M{
		"observable_type": record.ObservableType,
		"observable":      record.Observable,
		"status":          record.Status,
		"summary":         record.Summary,
		"queried_at":      record.QueriedAt,
		"expires_at":      record.ExpiresAt,
	}
	_, err := w.mongo.Collection("events").UpdateOne(ctx, bson.M{"_id": job.SourceEventID}, bson.M{"$set": bson.M{field: value}})
	return err
}

func (w *worker) queryProvider(ctx context.Context, job threatIntelJob) (enrichmentRecord, error) {
	now := time.Now().UTC()
	record := enrichmentRecord{
		ID: job.JobID, Provider: job.Provider, ObservableType: job.ObservableType,
		Observable: job.Observable, QueriedAt: now, ExpiresAt: now.Add(w.cfg.CacheTTL),
	}

	var apiKey string
	var perMinute, perDay int
	switch job.Provider {
	case "virustotal":
		apiKey, perMinute, perDay = w.cfg.VirusTotalKey, w.cfg.VTPerMinute, w.cfg.VTPerDay
	case "abuseipdb":
		apiKey, perMinute, perDay = w.cfg.AbuseIPDBKey, w.cfg.AbusePerMinute, w.cfg.AbusePerDay
	default:
		return record, fmt.Errorf("unsupported provider %q", job.Provider)
	}
	if apiKey == "" {
		record.Status = "skipped"
		record.Summary = map[string]any{"reason": "provider_not_configured"}
		record.ExpiresAt = now.Add(skippedCacheTTL)
		return record, nil
	}
	if err := w.reserveBudget(ctx, job.Provider, perMinute, perDay); err != nil {
		if deferred, ok := deferRecordForQuota(record, err); ok {
			return deferred, nil
		}
		return record, retryableError{err}
	}

	var summary map[string]any
	var status string
	var err error
	switch job.Provider {
	case "virustotal":
		status, summary, err = w.queryVirusTotal(ctx, job.Observable, apiKey)
	case "abuseipdb":
		status, summary, err = w.queryAbuseIPDB(ctx, job.Observable, apiKey)
	}
	if err != nil {
		if deferred, ok := deferRecordForQuota(record, err); ok {
			return deferred, nil
		}
		return record, err
	}
	record.Status = status
	record.Summary = summary
	return record, nil
}

func (w *worker) queryVirusTotal(ctx context.Context, hash, apiKey string) (string, map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/files/"+url.PathEscape(hash), nil)
	if err != nil {
		return "", nil, err
	}
	request.Header.Set("x-apikey", apiKey)
	request.Header.Set("Accept", "application/json")
	status, body, err := w.doRequest(request)
	if err != nil {
		return "", nil, err
	}
	if status == http.StatusNotFound {
		return "not_found", map[string]any{"known_to_provider": false}, nil
	}
	if status == http.StatusTooManyRequests {
		return "", nil, &quotaExhaustedError{provider: "virustotal", window: "provider", retryAfter: time.Minute}
	}
	if status >= 500 {
		return "", nil, retryableError{fmt.Errorf("VirusTotal HTTP %d", status)}
	}
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("VirusTotal HTTP %d", status)
	}
	var response struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				MeaningfulName    string         `json:"meaningful_name"`
				Reputation        int            `json:"reputation"`
				LastAnalysisStats map[string]any `json:"last_analysis_stats"`
				LastAnalysisDate  int64          `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", nil, fmt.Errorf("decode VirusTotal response: %w", err)
	}
	return "complete", map[string]any{
		"known_to_provider": true,
		"type":              response.Data.Type,
		"meaningful_name":   response.Data.Attributes.MeaningfulName,
		"reputation":        response.Data.Attributes.Reputation,
		"analysis_stats":    response.Data.Attributes.LastAnalysisStats,
		"analysis_unix":     response.Data.Attributes.LastAnalysisDate,
	}, nil
}

func (w *worker) queryAbuseIPDB(ctx context.Context, ip, apiKey string) (string, map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return "", nil, err
	}
	query := request.URL.Query()
	query.Set("ipAddress", ip)
	query.Set("maxAgeInDays", "90")
	request.URL.RawQuery = query.Encode()
	request.Header.Set("Key", apiKey)
	request.Header.Set("Accept", "application/json")
	status, body, err := w.doRequest(request)
	if err != nil {
		return "", nil, err
	}
	if status == http.StatusTooManyRequests {
		return "", nil, &quotaExhaustedError{provider: "abuseipdb", window: "provider", retryAfter: time.Minute}
	}
	if status >= 500 {
		return "", nil, retryableError{fmt.Errorf("AbuseIPDB HTTP %d", status)}
	}
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("AbuseIPDB HTTP %d", status)
	}
	var response struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			Domain               string `json:"domain"`
			IsTor                bool   `json:"isTor"`
			ISP                  string `json:"isp"`
			TotalReports         int    `json:"totalReports"`
			UsageType            string `json:"usageType"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", nil, fmt.Errorf("decode AbuseIPDB response: %w", err)
	}
	return "complete", map[string]any{
		"abuse_confidence_score": response.Data.AbuseConfidenceScore,
		"total_reports":          response.Data.TotalReports,
		"country_code":           response.Data.CountryCode,
		"usage_type":             response.Data.UsageType,
		"domain":                 response.Data.Domain,
		"isp":                    response.Data.ISP,
		"is_tor":                 response.Data.IsTor,
	}, nil
}

func (w *worker) doRequest(request *http.Request) (int, []byte, error) {
	response, err := w.client.Do(request)
	if err != nil {
		return 0, nil, retryableError{err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, providerBodyLimit))
	if err != nil {
		return 0, nil, retryableError{err}
	}
	return response.StatusCode, body, nil
}

func (w *worker) reserveBudget(ctx context.Context, provider string, perMinute, perDay int) error {
	if perMinute > 0 {
		key := "ti:quota:" + provider + ":minute:" + time.Now().UTC().Format("200601021504")
		count, err := w.redis.Incr(ctx, key).Result()
		if err != nil {
			return fmt.Errorf("increment minute quota: %w", err)
		}
		if count == 1 {
			_ = w.redis.Expire(ctx, key, 2*time.Minute).Err()
		}
		if count > int64(perMinute) {
			return &quotaExhaustedError{provider: provider, window: "minute", retryAfter: untilNextMinute(time.Now().UTC())}
		}
	}
	if perDay > 0 {
		key := "ti:quota:" + provider + ":day:" + time.Now().UTC().Format("20060102")
		count, err := w.redis.Incr(ctx, key).Result()
		if err != nil {
			return fmt.Errorf("increment daily quota: %w", err)
		}
		if count == 1 {
			_ = w.redis.Expire(ctx, key, 26*time.Hour).Err()
		}
		if count > int64(perDay) {
			return &quotaExhaustedError{provider: provider, window: "day", retryAfter: untilNextUTCDay(time.Now().UTC())}
		}
	}
	return nil
}

func (w *worker) ensureIndexes(ctx context.Context) error {
	_, err := w.mongo.Collection("threat_intel").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		{Keys: bson.D{{Key: "provider", Value: 1}, {Key: "observable", Value: 1}}},
	})
	return err
}

func ensureGroup(ctx context.Context, rdb *redis.Client, stream, group string) error {
	err := rdb.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

func decodeJob(message redis.XMessage) (threatIntelJob, error) {
	raw, ok := message.Values["job_json"]
	if !ok {
		return threatIntelJob{}, errors.New("job_json is missing")
	}
	var job threatIntelJob
	if err := json.Unmarshal([]byte(fmt.Sprint(raw)), &job); err != nil {
		return threatIntelJob{}, err
	}
	return job, nil
}

func validateJob(job threatIntelJob) error {
	if job.JobID == "" || job.SourceEventID == "" || job.Observable == "" {
		return errors.New("job_id, source_event_id, and observable are required")
	}
	if job.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported job schema %q", job.SchemaVersion)
	}
	switch job.Provider {
	case "virustotal":
		if job.ObservableType != "sha256" || len(job.Observable) != 64 {
			return errors.New("VirusTotal requires a SHA-256 observable")
		}
		if _, err := hex.DecodeString(job.Observable); err != nil {
			return errors.New("VirusTotal observable is not hexadecimal")
		}
	case "abuseipdb":
		if job.ObservableType != "ip" {
			return errors.New("AbuseIPDB requires an IP observable")
		}
		addr, err := netip.ParseAddr(job.Observable)
		if err != nil || !isQueryablePublicIP(addr.Unmap()) {
			return errors.New("AbuseIPDB requires a public IP observable")
		}
	default:
		return fmt.Errorf("unsupported provider %q", job.Provider)
	}
	return nil
}

func isQueryablePublicIP(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

func (w *worker) ack(ctx context.Context, stream, id string) {
	if err := w.redis.XAck(ctx, stream, w.cfg.Group, id).Err(); err != nil {
		log.Printf("xack failed stream=%s id=%s: %v", stream, id, err)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value, err := strconv.Atoi(getenv(key, strconv.Itoa(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(getenv(key, fallback.String()))
	if err != nil {
		return fallback
	}
	return value
}

func hostnameOr(fallback string) string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return fallback
	}
	return name
}
