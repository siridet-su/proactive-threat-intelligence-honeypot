package main

import (
	"errors"
	"fmt"
	"time"
)

// quotaExhaustedError is intentionally non-retryable at the stream level.
// The worker stores a short-lived deferred record and acknowledges the job so
// a provider limit cannot turn into an unbounded pending-entry list.
type quotaExhaustedError struct {
	provider   string
	window     string
	retryAfter time.Duration
}

func (e *quotaExhaustedError) Error() string {
	return fmt.Sprintf("%s %s quota exhausted", e.provider, e.window)
}

func deferRecordForQuota(record enrichmentRecord, err error) (enrichmentRecord, bool) {
	var quotaErr *quotaExhaustedError
	if !errors.As(err, &quotaErr) {
		return record, false
	}
	retryAfter := quotaErr.retryAfter
	if retryAfter <= 0 {
		retryAfter = time.Minute
	}
	record.Status = "deferred"
	record.Summary = map[string]any{
		"reason": "quota_exhausted",
		"window": quotaErr.window,
	}
	record.ExpiresAt = record.QueriedAt.Add(retryAfter)
	return record, true
}

func untilNextMinute(now time.Time) time.Duration {
	return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

func untilNextUTCDay(now time.Time) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return next.Sub(now)
}
