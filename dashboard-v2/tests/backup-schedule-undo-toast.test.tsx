// @vitest-environment happy-dom
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackupScheduleSettings } from "../src/components/dashboard/BackupScheduleSettings";
import type { BackupScheduleView } from "../src/lib/backupSchedule";

MotionGlobalConfig.skipAnimations = true;

const current: BackupScheduleView = {
  timezone: "Asia/Bangkok",
  local_date: "2026-09-27",
  revision: "revision-1",
  settings: { base_time: "03:30", override: null },
  preview: { next_run_at: "2026-09-28T01:00:00Z", catch_up: false, return_at: null, effective_time: "03:30" },
  today_run_status: "success",
  retry_after: null,
  worker_ready: true,
  can_edit: true,
  updated_at: null,
};

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("backup schedule Undo", () => {
  it("does not write during the Undo window and sends the previewed edit after it", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/preview")) return { ok: true, json: async () => ({ revision: current.revision, settings: { base_time: "01:00", override: null }, preview: current.preview, unchanged: false }) };
      if (init?.method === "POST") return { ok: true, json: async () => ({ ...current, revision: "revision-2", settings: { base_time: "01:00", override: null }, unchanged: false }) };
      return { ok: true, json: async () => current };
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<BackupScheduleSettings />);
    await screen.findByText("Change schedule");

    fireEvent.click(screen.getByRole("button", { name: "01:00" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview change" }));
    await screen.findByRole("button", { name: "Save schedule" });

    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    expect(screen.getByRole("button", { name: "Undo" })).toBeTruthy();
    expect(fetchMock.mock.calls.filter(([path, init]) => String(path) === "/api/backup/schedule" && init?.method === "POST")).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(screen.queryByText("Change canceled")).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(3_000); });
    expect(screen.queryByRole("button", { name: "Undo" })).toBeNull();
    expect(fetchMock.mock.calls.filter(([path, init]) => String(path) === "/api/backup/schedule" && init?.method === "POST")).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(2_999); });
    expect(fetchMock.mock.calls.filter(([path, init]) => String(path) === "/api/backup/schedule" && init?.method === "POST")).toHaveLength(0);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    const writes = fetchMock.mock.calls.filter(([path, init]) => String(path) === "/api/backup/schedule" && init?.method === "POST");
    expect(writes).toHaveLength(1);
    expect(JSON.parse(String(writes[0]?.[1]?.body))).toEqual({ edit: { mode: "permanent", time: "01:00" }, expected_revision: "revision-1" });
    expect(screen.getByText("Schedule saved")).toBeTruthy();
  });

  it("disables Save when the server preview reports no change", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/preview")) return { ok: true, json: async () => ({ revision: current.revision, settings: current.settings, preview: current.preview, unchanged: true }) };
      if (init?.method === "POST") throw new Error("Unexpected schedule write");
      return { ok: true, json: async () => current };
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<BackupScheduleSettings />);
    await screen.findByText("Change schedule");

    fireEvent.click(screen.getByRole("button", { name: "Preview change" }));
    const save = await screen.findByRole("button", { name: "Save schedule" });
    expect(save.hasAttribute("disabled")).toBe(true);
    expect(screen.getByText("These settings already match the current schedule.")).toBeTruthy();
    fireEvent.click(save);
    expect(fetchMock.mock.calls.filter(([path, init]) => String(path) === "/api/backup/schedule" && init?.method === "POST")).toHaveLength(0);
  });
});
