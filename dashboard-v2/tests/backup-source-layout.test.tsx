// @vitest-environment happy-dom
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackupSourceMap } from "../src/components/dashboard/BackupSourceMap";
import type { BackupTargetOverview, HardwareBackupDay, BackupTargetId } from "../src/lib/dashboardTypes";

vi.mock("../src/components/dashboard/HardwareBackupStatus", () => ({
  HardwareBackupStatus: () => <div data-testid="hardware-detail">Hardware detail loaded</div>,
}));

MotionGlobalConfig.skipAnimations = true;

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("backup source layout", () => {
  it("keeps hardware actions and operational detail collapsed until requested", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render(<BackupSourceMap />);

    const hardwareButton = screen.getByRole("button", { name: /Hardware actions & destination/ });
    const operationsButton = screen.getByRole("button", { name: /Activity, recovery & policy/ });
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("false");
    expect(operationsButton.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByTestId("hardware-detail")).toBeNull();

    fireEvent.click(hardwareButton);
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByTestId("hardware-detail")).toBeTruthy();

    fireEvent.click(hardwareButton);
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(operationsButton);
    expect(operationsButton.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByLabelText("Loading backup details")).toBeTruthy();
  });

  it("aligns all three sources on one shared calendar and pages their history together", async () => {
    const targetIds: BackupTargetId[] = ["hardware_metrics_1m", "threat_events", "filesystem_audit"];
    const day = (date: string, status: HardwareBackupDay["status"], objectName: string | null): HardwareBackupDay => ({
      day: date, status, object_name: objectName, document_count: status === "success" ? (objectName ? 3 : 0) : null,
      archive_bytes: 0, started_at: null, completed_at: null, error: null,
    });
    const overview: BackupTargetOverview = {
      generated_at: "2026-09-29T00:00:00Z", active_count: 3, planned_count: 0,
      worker: { state: "healthy", mode: "control", poll_seconds: 15, last_seen_at: null,
        heartbeat_age_seconds: 1, target_count: 3, attention_count: 0 },
      destination: null,
      policy: { lookback_days: 30, safety_days: 2, eligible_days: 29, schedule: "daily", archive_format: "gzip",
        destination_visibility: "private", sensitive_target_policy: "opt-in" },
      restore: { status: "not_tested", last_verified_at: null, detail: "", source: "" },
      exceptions: [], activity: [],
      targets: targetIds.map((targetId, index) => ({
        target_id: targetId, state: "active", collections: [targetId], sensitive: false,
        last_seen_at: null, last_completed_at: null,
        coverage: { expected_days: 1, successful_days: index < 2 ? 1 : 0, archived_days: index === 0 ? 1 : 0,
          empty_days: index === 1 ? 1 : 0, failed_days: index === 2 ? 1 : 0, running_days: 0, missing_days: 0,
          archived_documents: index === 0 ? 3 : 0, archive_bytes: 0, latest_success_day: null, lag_days: 0,
          last_started_at: null, last_completed_at: null, latest_run_status: null },
        days: [day("2026-09-26", index === 2 ? "failed" : "success", index === 0 ? "archive.gz" : null)],
      })),
    };
    vi.stubGlobal("fetch", vi.fn((input: string) => Promise.resolve({ ok: true, json: async () =>
      input.includes("/history")
        ? { period: 1, expected_window: { from: "2026-08-29", to: "2026-08-29", days: 1 }, has_older: false,
            targets: targetIds.map((targetId) => ({ target_id: targetId, days: [day("2026-08-29", "missing", null)] })) }
        : overview,
    })));
    render(<BackupSourceMap />);

    await waitFor(() => expect(screen.getByRole("table", { name: "Daily manifest status by archive source" })).toBeTruthy());
    expect(screen.getByRole("cell", { name: "Hardware rollups, 2026-09-26: Archived · 3 records" })).toBeTruthy();
    expect(screen.getByRole("cell", { name: "Threat event history, 2026-09-26: Empty check · no source records or B2 object" })).toBeTruthy();
    expect(screen.getByRole("cell", { name: "Filesystem audit history, 2026-09-26: Failed" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(screen.getByRole("cell", { name: "Threat event history, 2026-08-29: Missing manifest" })).toBeTruthy());
    expect(screen.getByRole("cell", { name: "Filesystem audit history, 2026-08-29: Missing manifest" })).toBeTruthy();
  });
});
