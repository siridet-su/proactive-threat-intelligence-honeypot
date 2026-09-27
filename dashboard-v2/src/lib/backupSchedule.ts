import { ObjectId, type Document, type Db } from "mongodb";

import { getMongoClient, getMongoDatabaseName } from "./mongodb";

export const BACKUP_SCHEDULE_SCHEMA = "pti.backup_schedule.v1";
const REVISION_COLLECTION = "backup_schedule_revisions";
const RUN_COLLECTION = "backup_schedule_runs";
const TARGET_STATUS_COLLECTION = "backup_target_status";
const DAY_MS = 86_400_000;
const BANGKOK_OFFSET_MS = 7 * 3_600_000;

export type BackupScheduleOverride = { start_date: string; days: number; time: string };
export type BackupScheduleSettings = { base_time: string; override: BackupScheduleOverride | null };
export type BackupScheduleEdit =
  | { mode: "permanent"; time: string }
  | { mode: "temporary"; time: string; start_date: string; days: number }
  | { mode: "clear_override" };
export type BackupScheduleRunStatus = "running" | "success" | "failed" | null;
export type BackupSchedulePreview = {
  next_run_at: string;
  catch_up: boolean;
  return_at: string | null;
  effective_time: string;
};
export type BackupScheduleView = {
  timezone: "Asia/Bangkok";
  local_date: string;
  revision: string;
  settings: BackupScheduleSettings;
  preview: BackupSchedulePreview;
  today_run_status: BackupScheduleRunStatus;
  retry_after: string | null;
  worker_ready: boolean;
  can_edit: boolean;
  updated_at: string | null;
};

export function bangkokDate(now: Date): string {
  return new Date(now.getTime() + BANGKOK_OFFSET_MS).toISOString().slice(0, 10);
}

export function addLocalDays(day: string, days: number): string {
  return new Date(Date.parse(`${day}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}

export function validDailyTime(value: unknown): value is string {
  return typeof value === "string" && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value);
}

export function validLocalDate(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

export function applyScheduleEdit(settings: BackupScheduleSettings, edit: BackupScheduleEdit, today: string): BackupScheduleSettings {
  if (edit.mode === "clear_override") return { ...settings, override: null };
  if (!validDailyTime(edit.time)) throw new Error("Choose a valid time in HH:mm format");
  if (edit.mode === "permanent") return { ...settings, base_time: edit.time };
  if (!validLocalDate(edit.start_date) || edit.start_date < today || edit.start_date > addLocalDays(today, 365)) {
    throw new Error("Choose a start date from today through the next year");
  }
  if (!Number.isInteger(edit.days) || edit.days < 1 || edit.days > 90) {
    throw new Error("Temporary schedules must last 1–90 days");
  }
  return { ...settings, override: { start_date: edit.start_date, days: edit.days, time: edit.time } };
}

export function effectiveScheduleTime(settings: BackupScheduleSettings, localDay: string): string {
  const override = settings.override;
  if (override && localDay >= override.start_date && localDay < addLocalDays(override.start_date, override.days)) {
    return override.time;
  }
  return settings.base_time;
}

export function scheduledOccurrence(localDay: string, time: string): Date {
  const [hours, minutes] = time.split(":").map(Number);
  return new Date(Date.parse(`${localDay}T00:00:00Z`) + (hours * 60 + minutes) * 60_000 - BANGKOK_OFFSET_MS);
}

export function lastScheduledOccurrence(settings: BackupScheduleSettings, now: Date): Date {
  const today = bangkokDate(now);
  const todayOccurrence = scheduledOccurrence(today, effectiveScheduleTime(settings, today));
  if (todayOccurrence <= now) return todayOccurrence;
  const yesterday = addLocalDays(today, -1);
  return scheduledOccurrence(yesterday, effectiveScheduleTime(settings, yesterday));
}

export function previewSchedule(settings: BackupScheduleSettings, now: Date, todayRun: BackupScheduleRunStatus, retryAfter: Date | null = null): BackupSchedulePreview {
  const today = bangkokDate(now);
  const effectiveTime = effectiveScheduleTime(settings, today);
  const todayOccurrence = scheduledOccurrence(today, effectiveTime);
  const tomorrow = addLocalDays(today, 1);
  const nextDayOccurrence = scheduledOccurrence(tomorrow, effectiveScheduleTime(settings, tomorrow));
  let next = todayOccurrence;
  let catchUp = false;
  if (todayRun === "success" || todayRun === "running") {
    next = nextDayOccurrence;
  } else if (todayOccurrence <= now) {
    next = todayRun === "failed" && retryAfter && retryAfter > now ? retryAfter : now;
    catchUp = true;
  }
  const returnAt = settings.override
    ? scheduledOccurrence(addLocalDays(settings.override.start_date, settings.override.days), settings.base_time).toISOString()
    : null;
  return { next_run_at: next.toISOString(), catch_up: catchUp, return_at: returnAt, effective_time: effectiveTime };
}

function parseSettings(document: Document | null): BackupScheduleSettings {
  if (!document) return { base_time: "03:30", override: null };
  if (document.schema_version !== BACKUP_SCHEDULE_SCHEMA || !validDailyTime(document.base_time)) {
    throw new Error("Backup schedule configuration is invalid");
  }
  const raw = document.override;
  if (raw === null || raw === undefined) return { base_time: document.base_time, override: null };
  if (!validLocalDate(raw.start_date) || !Number.isInteger(raw.days) || raw.days < 1 || raw.days > 90 || !validDailyTime(raw.time)) {
    throw new Error("Temporary backup schedule is invalid");
  }
  return { base_time: document.base_time, override: { start_date: raw.start_date, days: raw.days, time: raw.time } };
}

async function database(): Promise<Db> {
  const client = await getMongoClient();
  return client.db(getMongoDatabaseName());
}

async function latestRevision(db: Db): Promise<Document | null> {
  return db.collection(REVISION_COLLECTION).findOne({}, { sort: { sequence: -1 } });
}

export async function getBackupScheduleView(canEdit: boolean, now = new Date()): Promise<BackupScheduleView> {
  const db = await database();
  const today = bangkokDate(now);
  const [revision, run, worker] = await Promise.all([
    latestRevision(db),
    db.collection<{ _id: string; status?: string; retry_after?: Date }>(RUN_COLLECTION).findOne({ _id: today }),
    db.collection(TARGET_STATUS_COLLECTION).findOne({ target_id: "hardware_metrics_1m", enabled: true }, { projection: { scheduler_version: 1, last_seen_at: 1, mode: 1 } }),
  ]);
  const settings = parseSettings(revision);
  const runStatus: BackupScheduleRunStatus = run?.status === "success" || run?.status === "running" || run?.status === "failed" ? run.status : null;
  const seen = worker?.last_seen_at instanceof Date ? worker.last_seen_at.getTime() : 0;
  return {
    timezone: "Asia/Bangkok",
    local_date: today,
    revision: revision?._id instanceof ObjectId ? revision._id.toHexString() : "default",
    settings,
    preview: previewSchedule(settings, now, runStatus, run?.retry_after instanceof Date ? run.retry_after : null),
    today_run_status: runStatus,
    retry_after: run?.retry_after instanceof Date ? run.retry_after.toISOString() : null,
    worker_ready: worker?.scheduler_version === BACKUP_SCHEDULE_SCHEMA && worker?.mode === "control" && now.getTime() - seen < 90_000,
    can_edit: canEdit,
    updated_at: revision?.created_at instanceof Date ? revision.created_at.toISOString() : null,
  };
}

export async function getBackupCoverageAnchor(now = new Date()): Promise<Date> {
  const db = await database();
  const settings = parseSettings(await latestRevision(db));
  return lastScheduledOccurrence(settings, now);
}

export async function previewBackupScheduleEdit(edit: BackupScheduleEdit, now = new Date()): Promise<{ revision: string; settings: BackupScheduleSettings; preview: BackupSchedulePreview }> {
  const current = await getBackupScheduleView(true, now);
  const settings = applyScheduleEdit(current.settings, edit, bangkokDate(now));
  return { revision: current.revision, settings, preview: previewSchedule(settings, now, current.today_run_status, current.retry_after ? new Date(current.retry_after) : null) };
}

export async function saveBackupSchedule(edit: BackupScheduleEdit, expectedRevision: string, operatorId: string): Promise<BackupScheduleView> {
  const db = await database();
  const now = new Date();
  const worker = await db.collection(TARGET_STATUS_COLLECTION).findOne({ target_id: "hardware_metrics_1m", enabled: true }, { projection: { scheduler_version: 1, last_seen_at: 1, mode: 1 } });
  const seen = worker?.last_seen_at instanceof Date ? worker.last_seen_at.getTime() : 0;
  if (worker?.scheduler_version !== BACKUP_SCHEDULE_SCHEMA || worker?.mode !== "control" || now.getTime() - seen >= 90_000) {
    throw new Error("Pi schedule worker is not ready");
  }
  const previous = await latestRevision(db);
  const parent = previous?._id instanceof ObjectId ? previous._id.toHexString() : "default";
  if (expectedRevision !== parent) throw new Error("Backup schedule changed; refresh and try again");
  const settings = applyScheduleEdit(parseSettings(previous), edit, bangkokDate(now));
  await db.collection(REVISION_COLLECTION).createIndex({ parent_id: 1 }, { unique: true });
  await db.collection(REVISION_COLLECTION).insertOne({
    schema_version: BACKUP_SCHEDULE_SCHEMA,
    parent_id: parent,
    sequence: typeof previous?.sequence === "number" ? previous.sequence + 1 : 1,
    base_time: settings.base_time,
    override: settings.override,
    updated_by: operatorId,
    created_at: now,
  });
  return getBackupScheduleView(true);
}
