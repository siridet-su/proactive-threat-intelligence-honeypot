import { describe, expect, it } from "vitest";

import {
  applyScheduleEdit,
  lastScheduledOccurrence,
  previewSchedule,
  type BackupScheduleSettings,
} from "../src/lib/backupSchedule";
import { getHardwareBackupWindow } from "../src/lib/hardware-backup";

const base: BackupScheduleSettings = { base_time: "03:30", override: null };

describe("daily backup schedule", () => {
  it("uses the most recent Bangkok occurrence for UTC coverage after 07:00", () => {
    const now = new Date("2026-09-28T09:00:00Z"); // 16:00 Bangkok
    const occurrence = lastScheduledOccurrence(base, now);
    expect(occurrence.toISOString()).toBe("2026-09-27T20:30:00.000Z");
    const window = getHardwareBackupWindow(occurrence);
    expect(window.to.toISOString()).toBe("2026-09-25T00:00:00.000Z");
  });

  it("runs once promptly when today's new time has passed, then returns to base", () => {
    const now = new Date("2026-09-27T19:00:00Z"); // 02:00 Bangkok on Sep 28
    const settings = applyScheduleEdit(base, { mode: "temporary", time: "01:00", start_date: "2026-09-28", days: 7 }, "2026-09-28");
    const preview = previewSchedule(settings, now, null);
    expect(preview.catch_up).toBe(true);
    expect(preview.next_run_at).toBe(now.toISOString());
    expect(preview.return_at).toBe("2026-10-04T20:30:00.000Z");
    expect(previewSchedule(settings, now, "success").next_run_at).toBe("2026-09-28T18:00:00.000Z");
    expect(applyScheduleEdit(settings, { mode: "permanent", time: "02:00" }, "2026-09-28").override).toEqual(settings.override);
  });

  it("rejects invalid dates, times, and oversized temporary changes", () => {
    expect(() => applyScheduleEdit(base, { mode: "temporary", time: "01:00", start_date: "2026-02-30", days: 7 }, "2026-01-01")).toThrow();
    expect(() => applyScheduleEdit(base, { mode: "temporary", time: "01:00", start_date: "2026-09-28", days: 91 }, "2026-09-28")).toThrow();
    expect(() => applyScheduleEdit(base, { mode: "permanent", time: "25:00" }, "2026-09-28")).toThrow();
  });
});
