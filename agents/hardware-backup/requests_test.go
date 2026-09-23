package main

import (
	"testing"
	"time"
)

func TestBackupWindowUsesSafetyDays(t *testing.T) {
	cfg := Config{LookbackDays: 30, SafetyDays: 2}
	days := backupWindow(cfg, time.Date(2026, 9, 23, 12, 0, 0, 0, time.FixedZone("ICT", 7*60*60)))

	if len(days) != 29 {
		t.Fatalf("backupWindow() returned %d days, want 29", len(days))
	}
	if got := days[0].Format("2006-01-02"); got != "2026-08-24" {
		t.Fatalf("first backup day = %s, want 2026-08-24", got)
	}
	if got := days[len(days)-1].Format("2006-01-02"); got != "2026-09-21" {
		t.Fatalf("last backup day = %s, want 2026-09-21", got)
	}
}

func TestProgressPercent(t *testing.T) {
	tests := []struct {
		completed int
		total     int
		want      int
	}{
		{completed: 0, total: 0, want: 100},
		{completed: 0, total: 29, want: 0},
		{completed: 14, total: 29, want: 48},
		{completed: 29, total: 29, want: 100},
	}

	for _, test := range tests {
		if got := progressPercent(test.completed, test.total); got != test.want {
			t.Errorf("progressPercent(%d, %d) = %d, want %d", test.completed, test.total, got, test.want)
		}
	}
}
