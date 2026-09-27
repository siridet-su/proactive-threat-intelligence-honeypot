import { describe, expect, it } from "vitest";

import { buildBackupTargetCoverage, buildBackupTargetExceptions, getHardwareBackupWindow } from "@/lib/hardware-backup";
import { isBackupTargetOverview, isHardwareBackupStatus } from "@/lib/dashboardTypes";

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
      storage: {
        source: "hardware_metrics_1m",
        bucket: "pti-hardware-backups",
        storage_bytes: 12_345_678,
        file_versions: 29,
        checked_at: "2026-09-23T15:03:00.000Z",
      },
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
      storage: null,
    })).toBe(true);
  });

  it("summarizes manifest coverage per target, including empty days", () => {
    const window = getHardwareBackupWindow(new Date("2026-09-23T12:00:00.000Z"));
    const coverage = buildBackupTargetCoverage([
      {
        target_id: "threat_events",
        day_start: new Date("2026-09-19T00:00:00.000Z"),
        status: "success",
        document_count: 0,
        archive_bytes: 0,
        started_at: new Date("2026-09-23T15:00:00.000Z"),
        completed_at: new Date("2026-09-23T15:00:01.000Z"),
        object_name: null,
      },
      {
        target_id: "threat_events",
        day_start: new Date("2026-09-20T00:00:00.000Z"),
        status: "success",
        document_count: 4,
        archive_bytes: 100,
        started_at: new Date("2026-09-23T15:01:00.000Z"),
        completed_at: new Date("2026-09-23T15:01:01.000Z"),
        object_name: "threat_events/2026/09/20/archive.jsonl.gz",
      },
      {
        target_id: "threat_events",
        day_start: new Date("2026-09-21T00:00:00.000Z"),
        status: "failed",
        error: "temporary upload failure",
        started_at: new Date("2026-09-23T15:02:00.000Z"),
        completed_at: new Date("2026-09-23T15:02:01.000Z"),
      },
    ], "threat_events", window);

    expect(coverage.expected_days).toBe(29);
    expect(coverage.successful_days).toBe(2);
    expect(coverage.archived_days).toBe(1);
    expect(coverage.empty_days).toBe(1);
    expect(coverage.failed_days).toBe(1);
    expect(coverage.missing_days).toBe(26);
    expect(coverage.archived_documents).toBe(4);
    expect(coverage.archive_bytes).toBe(100);
    expect(coverage.latest_success_day).toBe("2026-09-20");
    expect(coverage.lag_days).toBe(1);
    expect(coverage.latest_run_status).toBe("failed");

    const exceptions = buildBackupTargetExceptions([
      {
        target_id: "threat_events",
        day_start: new Date("2026-09-21T00:00:00.000Z"),
        status: "failed",
        error: "temporary upload failure",
      },
    ], "threat_events", window);
    expect(exceptions.find((exception) => exception.day === "2026-09-21")).toMatchObject({
      target_id: "threat_events",
      day: "2026-09-21",
      status: "failed",
      detail: "temporary upload failure",
      action_supported: false,
    });
  });

  it("accepts target coverage summaries from the backup overview API", () => {
    expect(isBackupTargetOverview({
      generated_at: "2026-09-23T15:00:00.000Z",
      active_count: 2,
      planned_count: 1,
      targets: [{
        target_id: "filesystem_audit",
        state: "active",
        collections: ["cwd_events", "cwd_session_state"],
        sensitive: false,
        last_seen_at: "2026-09-23T15:00:00.000Z",
        last_completed_at: "2026-09-23T15:02:00.000Z",
        coverage: {
          expected_days: 29,
          successful_days: 29,
          archived_days: 28,
          empty_days: 1,
          failed_days: 0,
          running_days: 0,
          missing_days: 0,
          archived_documents: 1_878,
          archive_bytes: 12_345,
          latest_success_day: "2026-09-21",
          lag_days: 0,
          last_started_at: "2026-09-23T15:00:00.000Z",
          last_completed_at: "2026-09-23T15:02:00.000Z",
          latest_run_status: "success",
        },
      }],
      worker: {
        state: "healthy",
        mode: "control",
        poll_seconds: 15,
        last_seen_at: "2026-09-23T15:00:00.000Z",
        heartbeat_age_seconds: 10,
        target_count: 2,
        attention_count: 0,
      },
      destination: null,
      policy: {
        lookback_days: 30,
        safety_days: 2,
        eligible_days: 29,
        schedule: "Daily systemd timer",
        archive_format: "gzip Extended JSON Lines",
        destination_visibility: "Private Backblaze B2",
        sensitive_target_policy: "Threat events require explicit opt-in",
      },
      restore: {
        status: "not_tested",
        last_verified_at: null,
        detail: "No restore rehearsal has been recorded yet.",
        source: "Read-only restore operator path",
      },
      exceptions: [],
      activity: [],
    })).toBe(true);
  });
});
