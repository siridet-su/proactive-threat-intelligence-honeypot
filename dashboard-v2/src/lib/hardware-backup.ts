import type { Document } from "mongodb";

import { getMongoClient, getMongoDatabaseName } from "./mongodb";
import type {
  HardwareBackupDay,
  HardwareBackupDayStatus,
  HardwareBackupStatus,
} from "./dashboardTypes";

const BACKUP_COLLECTION = "hardware_backup_manifests";
const HARDWARE_COLLECTION = "hardware_metrics_1m";
const LOOKBACK_DAYS = 30;
const SAFETY_DAYS = 2;
const MAX_MANIFESTS = 90;

function asDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  if (typeof value !== "string" && typeof value !== "number") return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function asFiniteNumber(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (value && typeof value === "object" && "toString" in value) {
    const parsed = Number(String(value));
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function startOfUtcDay(value: Date): Date {
  return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
}

function addUtcDays(value: Date, days: number): Date {
  return new Date(value.getTime() + days * 24 * 60 * 60 * 1_000);
}

function dayKey(value: Date): string {
  return value.toISOString().slice(0, 10);
}

function dateValue(value: unknown): string | null {
  return asDate(value)?.toISOString() ?? null;
}

function statusValue(value: unknown): HardwareBackupDayStatus | null {
  return value === "success" || value === "failed" || value === "running" ? value : null;
}

function numberValue(value: unknown): number | null {
  const number = asFiniteNumber(value);
  return number === null ? null : Math.max(0, Math.floor(number));
}

function manifestDay(document: Document): HardwareBackupDay | null {
  const dayStart = asDate(document.day_start);
  if (!dayStart) return null;

  const status = statusValue(document.status) ?? "failed";
  return {
    day: dayKey(dayStart),
    status,
    document_count: numberValue(document.document_count),
    archive_bytes: numberValue(document.archive_bytes),
    started_at: dateValue(document.started_at),
    completed_at: dateValue(document.completed_at),
    object_name: typeof document.object_name === "string" ? document.object_name : null,
    error: typeof document.error === "string" ? document.error : null,
  };
}

function expectedDay(day: Date, manifest: HardwareBackupDay | undefined): HardwareBackupDay {
  return manifest ?? {
    day: dayKey(day),
    status: "missing",
    document_count: null,
    archive_bytes: null,
    started_at: null,
    completed_at: null,
    object_name: null,
    error: null,
  };
}

function latestDate(days: HardwareBackupDay[], field: "started_at" | "completed_at"): string | null {
  return days
    .map((day) => day[field])
    .filter((value): value is string => value !== null)
    .sort()
    .at(-1) ?? null;
}

export function getHardwareBackupWindow(now = new Date()) {
  const today = startOfUtcDay(now);
  const from = addUtcDays(today, -LOOKBACK_DAYS);
  const to = addUtcDays(today, -SAFETY_DAYS);
  const days = Math.floor((to.getTime() - from.getTime()) / (24 * 60 * 60 * 1_000)) + 1;
  return { from, to, days };
}

export async function getHardwareBackupStatus(): Promise<HardwareBackupStatus> {
  const window = getHardwareBackupWindow();
  const query: Document = {
    collection: HARDWARE_COLLECTION,
    day_start: { $gte: window.from, $lte: window.to },
  };
  const client = await getMongoClient();
  const documents = await client
    .db(getMongoDatabaseName())
    .collection(BACKUP_COLLECTION)
    .find(query)
    .project({
      day_start: 1,
      status: 1,
      document_count: 1,
      archive_bytes: 1,
      started_at: 1,
      completed_at: 1,
      object_name: 1,
      error: 1,
    })
    .sort({ day_start: 1 })
    .limit(MAX_MANIFESTS)
    .toArray();

  const manifests = new Map<string, HardwareBackupDay>();
  for (const document of documents) {
    const day = manifestDay(document);
    if (day) manifests.set(day.day, day);
  }

  const days: HardwareBackupDay[] = [];
  for (let day = window.from; day <= window.to; day = addUtcDays(day, 1)) {
    days.push(expectedDay(day, manifests.get(dayKey(day))));
  }

  const successfulDays = days.filter((day) => day.status === "success");
  const failedDays = days.filter((day) => day.status === "failed");
  const runningDays = days.filter((day) => day.status === "running");
  const archivedDocuments = successfulDays.reduce((total, day) => total + (day.document_count ?? 0), 0);
  const archiveBytes = successfulDays.reduce((total, day) => total + (day.archive_bytes ?? 0), 0);
  const latestRun = [...days]
    .filter((day) => day.started_at !== null)
    .sort((left, right) => (right.started_at ?? "").localeCompare(left.started_at ?? ""))[0] ?? null;

  return {
    collection: HARDWARE_COLLECTION,
    generated_at: new Date().toISOString(),
    expected_window: {
      from: window.from.toISOString(),
      to: window.to.toISOString(),
      days: window.days,
    },
    summary: {
      expected_days: window.days,
      successful_days: successfulDays.length,
      failed_days: failedDays.length,
      running_days: runningDays.length,
      missing_days: days.filter((day) => day.status === "missing").length,
      archived_documents: archivedDocuments,
      archive_bytes: archiveBytes,
      latest_success_day: successfulDays.at(-1)?.day ?? null,
      last_started_at: latestDate(days, "started_at"),
      last_completed_at: latestDate(days, "completed_at"),
      latest_run_status: latestRun?.status ?? null,
    },
    days,
  };
}
