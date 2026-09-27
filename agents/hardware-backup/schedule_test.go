package main

import (
	"testing"
	"time"
)

func TestDailyScheduleCatchUpAndTemporaryReturn(t *testing.T) {
	schedule := backupSchedule{
		BaseTime: "03:30",
		Override: &scheduleOverride{StartDate: "2026-09-28", Days: 7, Time: "01:00"},
	}
	if err := validateScheduleOverride(*schedule.Override); err != nil {
		t.Fatal(err)
	}
	if got := effectiveScheduleTime(schedule, "2026-09-27"); got != "03:30" {
		t.Fatalf("before override = %s", got)
	}
	if got := effectiveScheduleTime(schedule, "2026-10-04"); got != "01:00" {
		t.Fatalf("last override day = %s", got)
	}
	if got := effectiveScheduleTime(schedule, "2026-10-05"); got != "03:30" {
		t.Fatalf("after override = %s", got)
	}
	// 02:00 Bangkok is 19:00 on the preceding UTC day. Moving today's
	// schedule from 03:30 to 01:00 makes today's run due immediately.
	day, due := dueScheduleDay(schedule, time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC))
	if day != "2026-09-28" || !due {
		t.Fatalf("catch-up day=%s due=%t", day, due)
	}
	_, due = dueScheduleDay(schedule, time.Date(2026, 9, 27, 17, 59, 0, 0, time.UTC))
	if due {
		t.Fatal("temporary run became due before 01:00 Bangkok")
	}
}

func TestDailyScheduleRejectsUnboundedOrMalformedOverride(t *testing.T) {
	for _, override := range []scheduleOverride{
		{StartDate: "2026-02-30", Days: 7, Time: "01:00"},
		{StartDate: "2026-09-28", Days: 91, Time: "01:00"},
		{StartDate: "2026-09-28", Days: 7, Time: "24:00"},
	} {
		if err := validateScheduleOverride(override); err == nil {
			t.Errorf("accepted invalid override: %#v", override)
		}
	}
}
