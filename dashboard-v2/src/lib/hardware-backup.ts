import { randomUUID } from "crypto";
import type { Document } from "mongodb";

import { getMongoClient, getMongoDatabaseName } from "./mongodb";
import type {
  HardwareBackupDay,
  HardwareBackupDayStatus,
  HardwareBackupRequestAction,
  HardwareBackupRequestProgress,
  HardwareBackupRequestView,
  HardwareBackupStatus,
} from "./dashboardTypes";

const BACKUP_COLLECTION = "hardware_backup_manifests";
const REQUEST_COLLECTION = "hardware_backup_requests";
const REQUEST_SCHEMA_VERSION = "pti.hardware_backup_request.v1";
const HARDWARE_COLLECTION = "hardware_metrics_1m";
const LOOKBACK_DAYS = 30;
const SAFETY_DAYS = 2;
const MAX_MANIFESTS = 90;

function asDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) && value.getUTCFullYear() > 1 ? value : null;
  if (typeof value !== "string" && typeof value !== "number") return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.getUTCFullYear() > 1 ? date : null;
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

function requestActionValue(value: unknown): HardwareBackupRequestAction | null {
  return value === "run_missing" || value === "retry_failed" ? value : null;
}

function requestStatusValue(value: unknown): HardwareBackupRequestView["status"] | null {
  return value === "pending" || value === "running" || value === "success" || value === "failed" ? value : null;
}

function requestProgress(document: Document): HardwareBackupRequestProgress {
  const value = document.progress && typeof document.progress === "object" ? document.progress as Document : {};
  const totalDays = numberValue(value.total_days) ?? 0;
  const completedDays = numberValue(value.completed_days) ?? 0;
  const successfulDays = numberValue(value.successful_days) ?? 0;
  const failedDays = numberValue(value.failed_days) ?? 0;
  const percent = Math.min(100, Math.max(0, numberValue(value.percent) ?? 0));
  return {
    total_days: totalDays,
    completed_days: completedDays,
    successful_days: successfulDays,
    failed_days: failedDays,
    current_day: typeof value.current_day === "string" && value.current_day.trim() ? value.current_day : null,
    percent,
  };
}

function requestView(document: Document | null): HardwareBackupRequestView | null {
  if (!document || typeof document._id !== "string") return null;
  const action = requestActionValue(document.action);
  const status = requestStatusValue(document.status);
  const createdAt = dateValue(document.created_at);
  if (!action || !status || !createdAt) return null;

  return {
    id: document._id,
    source: typeof document.source === "string" ? document.source : HARDWARE_COLLECTION,
    action,
    requested_by: typeof document.requested_by === "string" ? document.requested_by : "unknown",
    status,
    created_at: createdAt,
    started_at: dateValue(document.started_at),
    completed_at: dateValue(document.completed_at),
    heartbeat_at: dateValue(document.heartbeat_at),
    progress: requestProgress(document),
    error: typeof document.error === "string" ? document.error : null,
  };
}

let requestIndexes: Promise<void> | null = null;

async function ensureRequestIndexes() {
  if (requestIndexes) return requestIndexes;
  requestIndexes = (async () => {
    const client = await getMongoClient();
    const collection = client.db(getMongoDatabaseName()).collection(REQUEST_COLLECTION);
    await Promise.all([
      collection.createIndex({ source: 1, created_at: -1 }, { name: "hardware_backup_request_history" }),
      collection.createIndex(
        { active_key: 1 },
        {
          unique: true,
          name: "hardware_backup_request_active_unique",
          partialFilterExpression: { active_key: { $exists: true } },
        },
      ),
    ]);
  })();
  return requestIndexes;
}

export type CreateHardwareBackupRequestResult =
  | { conflict: false; request: HardwareBackupRequestView }
  | { conflict: true; request: HardwareBackupRequestView };

export async function createHardwareBackupRequest(
  action: HardwareBackupRequestAction,
  requestedBy: string,
): Promise<CreateHardwareBackupRequestResult> {
  await ensureRequestIndexes();
  const client = await getMongoClient();
  const collection = client.db(getMongoDatabaseName()).collection(REQUEST_COLLECTION);
  const now = new Date();
  const id = randomUUID();
  const request: Document = {
    _id: id,
    schema_version: REQUEST_SCHEMA_VERSION,
    source: HARDWARE_COLLECTION,
    action,
    requested_by: requestedBy,
    status: "pending",
    created_at: now,
    started_at: null,
    completed_at: null,
    heartbeat_at: null,
    updated_at: now,
    active_key: HARDWARE_COLLECTION,
    progress: {
      total_days: 0,
      completed_days: 0,
      successful_days: 0,
      failed_days: 0,
      current_day: "",
      percent: 0,
    },
    error: null,
  };

  try {
    await collection.insertOne(request);
  } catch (error: unknown) {
    if (!isDuplicateKeyError(error)) throw error;
    const active = await collection.findOne(
      { source: HARDWARE_COLLECTION, status: { $in: ["pending", "running"] } },
      { sort: { created_at: -1 } },
    );
    const activeView = requestView(active);
    if (activeView) return { conflict: true, request: activeView };
    throw new Error("Another hardware backup request is being finalized; retry shortly");
  }

  return {
    conflict: false,
    request: {
      id,
      source: HARDWARE_COLLECTION,
      action,
      requested_by: requestedBy,
      status: "pending",
      created_at: now.toISOString(),
      started_at: null,
      completed_at: null,
      heartbeat_at: null,
      progress: {
        total_days: 0,
        completed_days: 0,
        successful_days: 0,
        failed_days: 0,
        current_day: null,
        percent: 0,
      },
      error: null,
    },
  };
}

function isDuplicateKeyError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === 11000);
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
  const database = client.db(getMongoDatabaseName());
  const [documents, latestRequest] = await Promise.all([
    database
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
      .toArray(),
    database.collection(REQUEST_COLLECTION).findOne(
      { source: HARDWARE_COLLECTION },
      {
        projection: {
          _id: 1,
          source: 1,
          action: 1,
          requested_by: 1,
          status: 1,
          created_at: 1,
          started_at: 1,
          completed_at: 1,
          heartbeat_at: 1,
          progress: 1,
          error: 1,
        },
        sort: { created_at: -1 },
      },
    ),
  ]);

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
    can_control: false,
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
    request: requestView(latestRequest),
  };
}
