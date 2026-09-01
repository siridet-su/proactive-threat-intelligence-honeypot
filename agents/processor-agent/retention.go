package main

import "time"

const (
	defaultEventRetention           = 30 * 24 * time.Hour
	defaultHardwareMetricsRetention = 48 * time.Hour
)

func getenvPositiveDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(getenv(key, fallback.String()))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func expiryAt(observedAt time.Time, retention time.Duration) time.Time {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return observedAt.UTC().Add(retention)
}

func setEventExpiry(event map[string]any, retention time.Duration) {
	observedAt, _ := event["timestamp"].(time.Time)
	event["expires_at"] = expiryAt(observedAt, retention)
}

func setHardwareMetricExpiry(metric map[string]interface{}, observedAt time.Time, retention time.Duration) {
	metric["timestamp"] = observedAt.UTC()
	metric["expires_at"] = expiryAt(observedAt, retention)
}
