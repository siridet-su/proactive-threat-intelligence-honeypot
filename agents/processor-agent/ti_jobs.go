package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const threatIntelSchemaVersion = "v1"

// ThreatIntelJob is the narrow contract between event ingestion and the
// asynchronous enrichment worker. It intentionally contains observables only;
// raw command text and downloaded artifacts never leave the event pipeline.
type ThreatIntelJob struct {
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

func enqueueThreatIntelJobs(
	ctx context.Context,
	rdb *redis.Client,
	cfg Config,
	source string,
	eventID string,
	eventType string,
	srcIP string,
	payload map[string]any,
) error {
	if !cfg.TIEnabled {
		return nil
	}

	maxLen := cfg.TIJobsMaxLen
	if maxLen <= 0 {
		maxLen = 50000
	}

	for _, job := range buildThreatIntelJobs(source, eventID, eventType, srcIP, payload) {
		jobJSON, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("marshal job %s: %w", job.JobID, err)
		}

		if _, err := rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: cfg.TIJobsStream,
			MaxLen: maxLen,
			Approx: true,
			Values: map[string]any{
				"job_id":   job.JobID,
				"job_json": string(jobJSON),
			},
		}).Result(); err != nil {
			return fmt.Errorf("xadd %s: %w", cfg.TIJobsStream, err)
		}
	}

	return nil
}

func buildThreatIntelJobs(source, eventID, eventType, srcIP string, payload map[string]any) []ThreatIntelJob {
	jobs := make([]ThreatIntelJob, 0, 2)
	sessionID := firstNonEmpty(getPayloadString(payload, "session"), getPayloadString(payload, "uid"))
	priority := "normal"
	if strings.Contains(strings.ToLower(eventType), "file") || strings.Contains(strings.ToLower(eventType), "download") {
		priority = "high"
	}

	if shouldEnrichSourceIP(source) && isQueryablePublicIP(srcIP) {
		jobs = append(jobs, newThreatIntelJob("abuseipdb", "ip", srcIP, eventID, sessionID, priority))
	}

	if hash := extractSHA256(source, payload); hash != "" {
		jobs = append(jobs, newThreatIntelJob("virustotal", "sha256", hash, eventID, sessionID, priority))
	}

	return jobs
}

func shouldEnrichSourceIP(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "cowrie", "zeek":
		return true
	default:
		return false
	}
}

func extractSHA256(source string, payload map[string]any) string {
	if source != "cowrie" && source != "zeek" {
		return ""
	}

	for _, key := range []string{"sha256", "sha256_hash", "shasum"} {
		if hash := normalizeSHA256(getPayloadString(payload, key)); hash != "" {
			return hash
		}
	}
	return ""
}

func newThreatIntelJob(provider, observableType, observable, eventID, sessionID, priority string) ThreatIntelJob {
	identity := provider + "|" + observableType + "|" + observable
	digest := sha256.Sum256([]byte(identity))

	return ThreatIntelJob{
		JobID:          hex.EncodeToString(digest[:]),
		Provider:       provider,
		ObservableType: observableType,
		Observable:     observable,
		SourceEventID:  eventID,
		SessionID:      sessionID,
		Priority:       priority,
		RequestedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		SchemaVersion:  threatIntelSchemaVersion,
	}
}

func isQueryablePublicIP(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}

	// Carrier-grade NAT space is not globally attributable to an attacker.
	sharedSpace := netip.MustParsePrefix("100.64.0.0/10")
	return !sharedSpace.Contains(addr)
}

func normalizeSHA256(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}
