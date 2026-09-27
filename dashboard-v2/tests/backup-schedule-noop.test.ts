import { ObjectId } from "mongodb";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { BACKUP_SCHEDULE_SCHEMA, previewBackupScheduleEdit, saveBackupSchedule } from "../src/lib/backupSchedule";
import { getMongoClient } from "../src/lib/mongodb";

vi.mock("../src/lib/mongodb", () => ({
  getMongoClient: vi.fn(),
  getMongoDatabaseName: () => "honeypot_db",
}));

const revision = {
  _id: new ObjectId(),
  schema_version: BACKUP_SCHEDULE_SCHEMA,
  sequence: 3,
  base_time: "02:00",
  override: null,
  created_at: new Date("2026-09-27T13:10:28Z"),
};
const insertOne = vi.fn();
const createIndex = vi.fn();
const findRevision = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  findRevision.mockResolvedValue(revision);
  const db = {
    collection: (name: string) => {
      if (name === "backup_schedule_revisions") return { findOne: findRevision, createIndex, insertOne };
      if (name === "backup_schedule_runs") return { findOne: vi.fn().mockResolvedValue(null) };
      if (name === "backup_target_status") return { findOne: vi.fn().mockResolvedValue(null) };
      throw new Error(`Unexpected collection: ${name}`);
    },
  };
  vi.mocked(getMongoClient).mockResolvedValue({ db: () => db } as never);
});

describe("backup schedule unchanged guard", () => {
  it("returns unchanged without inserting a revision for an identical direct save", async () => {
    const result = await saveBackupSchedule({ mode: "permanent", time: "02:00" }, revision._id.toHexString(), "admin");
    expect(result.unchanged).toBe(true);
    expect(result.revision).toBe(revision._id.toHexString());
    expect(createIndex).not.toHaveBeenCalled();
    expect(insertOne).not.toHaveBeenCalled();
  });

  it("still rejects a stale revision before considering a no-op", async () => {
    await expect(saveBackupSchedule({ mode: "permanent", time: "02:00" }, "old-revision", "admin")).rejects.toThrow("changed");
    expect(insertOne).not.toHaveBeenCalled();
  });

  it("marks identical preview settings but detects a changed time", async () => {
    const now = new Date("2026-09-27T13:12:00Z");
    expect((await previewBackupScheduleEdit({ mode: "permanent", time: "02:00" }, now)).unchanged).toBe(true);
    expect((await previewBackupScheduleEdit({ mode: "permanent", time: "03:00" }, now)).unchanged).toBe(false);
  });

  it("compares the entire temporary override, including its duration", async () => {
    findRevision.mockResolvedValue({ ...revision, override: { start_date: "2026-09-28", days: 7, time: "01:00" } });
    const now = new Date("2026-09-27T13:12:00Z");
    expect((await previewBackupScheduleEdit({ mode: "temporary", time: "01:00", start_date: "2026-09-28", days: 7 }, now)).unchanged).toBe(true);
    expect((await previewBackupScheduleEdit({ mode: "temporary", time: "01:00", start_date: "2026-09-28", days: 8 }, now)).unchanged).toBe(false);
  });
});
