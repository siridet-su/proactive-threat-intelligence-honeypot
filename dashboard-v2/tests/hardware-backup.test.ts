import { describe, expect, it } from "vitest";

import { getHardwareBackupWindow } from "@/lib/hardware-backup";
import { isHardwareBackupStatus } from "@/lib/dashboardTypes";

describe("hardware backup dashboard status", () => {
  it("uses the completed-day safety window", () => {
    const window = getHardwareBackupWindow(new Date("2026-09-23T12:00:00.000Z"));

    expect(window.from.toISOString()).toBe("2026-08-24T00:00:00.000Z");
    expect(window.to.toISOString()).toBe("2026-09-21T00:00:00.000Z");
    expect(window.days).toBe(29);
  });

  it("accepts the API shape used by the coverage panel", () => {
    expect(isHardwareBackupStatus({
      can_control: true,
      collection: "hardware_metrics_1m",
      generated_at: "2026-09-23T15:00:00.000Z",
      expected_window: {
        from: "2026-08-24T00:00:00.000Z",
        to: "2026-09-21T00:00:00.000Z",
        days: 29,
      },
      summary: {
        expected_days: 29,
        successful_days: 29,
        failed_days: 0,
        running_days: 0,
        missing_days: 0,
        archived_documents: 18_720,
        archive_bytes: 12_345,
        latest_success_day: "2026-09-21",
        last_started_at: "2026-09-23T15:00:00.000Z",
        last_completed_at: "2026-09-23T15:02:00.000Z",
        latest_run_status: "success",
      },
      days: [{
        day: "2026-09-21",
        status: "success",
        document_count: 1_440,
        archive_bytes: 1_024,
        started_at: "2026-09-23T15:01:00.000Z",
        completed_at: "2026-09-23T15:02:00.000Z",
        object_name: "hardware_metrics_1m/2026/09/21/rollup.jsonl.gz",
        error: null,
      }],
      request: null,
    })).toBe(true);
  });

  it("accepts an active Pi request with progress", () => {
    expect(isHardwareBackupStatus({
      can_control: true,
      collection: "hardware_metrics_1m",
      generated_at: "2026-09-23T15:00:00.000Z",
      expected_window: { from: "2026-08-24T00:00:00.000Z", to: "2026-09-21T00:00:00.000Z", days: 29 },
      summary: {
        expected_days: 29,
        successful_days: 20,
        failed_days: 0,
        running_days: 0,
        missing_days: 9,
        archived_documents: 28_800,
        archive_bytes: 12_345,
        latest_success_day: "2026-09-12",
        last_started_at: "2026-09-23T15:00:00.000Z",
        last_completed_at: "2026-09-23T15:02:00.000Z",
        latest_run_status: "success",
      },
      days: [],
      request: {
        id: "request-1",
        source: "hardware_metrics_1m",
        action: "run_missing",
        requested_by: "admin",
        status: "running",
        created_at: "2026-09-23T15:00:00.000Z",
        started_at: "2026-09-23T15:00:01.000Z",
        completed_at: null,
        heartbeat_at: "2026-09-23T15:01:00.000Z",
        progress: {
          total_days: 9,
          completed_days: 4,
          successful_days: 4,
          failed_days: 0,
          current_day: "2026-09-04",
          percent: 44,
        },
        error: null,
      },
    })).toBe(true);
  });
});
