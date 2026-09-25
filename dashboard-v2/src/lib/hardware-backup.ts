import { randomUUID } from "crypto";
import type { Document } from "mongodb";

import { getMongoClient, getMongoDatabaseName } from "./mongodb";
import type {
  HardwareBackupDay,
  HardwareBackupDayStatus,
  HardwareBackupRequestAction,
  HardwareBackupRequestProgress,
  HardwareBackupRequestView,
  HardwareBackupStorageStatus,
  HardwareBackupStatus,
  BackupActivityEntry,
  BackupTargetCoverage,
  BackupDestinationStatus,
  BackupException,
  BackupPolicy,
  BackupTargetId,
  BackupTargetOverview,
  BackupTargetState,
  BackupRestoreReadiness,
  BackupWorkerStatus,
} from "./dashboardTypes";

const BACKUP_COLLECTION = "hardware_backup_manifests";
const REQUEST_COLLECTION = "hardware_backup_requests";
const REQUEST_SCHEMA_VERSION = "pti.hardware_backup_request.v1";
const STORAGE_SNAPSHOT_COLLECTION = "b2_storage_snapshots";
const HARDWARE_COLLECTION = "hardware_metrics_1m";
const LOOKBACK_DAYS = 30;
const SAFETY_DAYS = 2;
const MAX_MANIFESTS = 90;
const TARGET_STATUS_COLLECTION = "backup_target_status";
const RESTORE_VERIFICATION_COLLECTION = "backup_restore_verifications";
const BACKUP_CONTROL_POLL_SECONDS = 15;
const BACKUP_HEALTHY_AFTER_SECONDS = BACKUP_CONTROL_POLL_SECONDS * 6;
const BACKUP_STALE_AFTER_SECONDS = 30 * 60;

const BACKUP_TARGET_CATALOG = [
  { target_id: "hardware_metrics_1m", collections: ["hardware_metrics_1m"], sensitive: false },
  { target_id: "threat_events", collections: ["events"], sensitive: true },
  { target_id: "filesystem_audit", collections: ["cwd_events", "cwd_session_state"], sensitive: false },
] as const;

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

function textValue(value: unknown, maxLength = 240): string | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const normalized = value.trim().replace(/\s+/g, " ");
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
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
    error: textValue(document.error),
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
    error: textValue(document.error),
  };
}

function destinationSnapshotView(document: Document | null, now = new Date()): BackupDestinationStatus | null {
  const storage = storageSnapshotView(document);
  if (!storage) return null;
  const checkedAt = asDate(storage.checked_at);
  return {
    ...storage,
    age_seconds: checkedAt ? Math.max(0, Math.floor((now.getTime() - checkedAt.getTime()) / 1_000)) : 0,
  };
}

function storageSnapshotView(document: Document | null): HardwareBackupStorageStatus | null {
  if (!document || typeof document.source !== "string" || typeof document.bucket !== "string") return null;
  const storageBytes = numberValue(document.storage_bytes);
  const fileVersions = numberValue(document.file_versions);
  const checkedAt = dateValue(document.checked_at);
  if (storageBytes === null || fileVersions === null || !checkedAt) return null;
  return {
    source: document.source,
    bucket: document.bucket,
    storage_bytes: storageBytes,
    file_versions: fileVersions,
    checked_at: checkedAt,
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

function manifestTargetId(document: Document): string | null {
  if (typeof document.target_id === "string" && document.target_id.trim()) return document.target_id;
  if (typeof document.collection === "string" && document.collection.trim()) return document.collection;
  return null;
}

export function buildBackupTargetCoverage(
  documents: Document[],
  targetId: BackupTargetId,
  window = getHardwareBackupWindow(),
): BackupTargetCoverage {
  const manifests = new Map<string, HardwareBackupDay>();
  for (const document of documents) {
    if (manifestTargetId(document) !== targetId) continue;
    const day = manifestDay(document);
    if (day) manifests.set(day.day, day);
  }

  const days: HardwareBackupDay[] = [];
  for (let day = window.from; day <= window.to; day = addUtcDays(day, 1)) {
    days.push(expectedDay(day, manifests.get(dayKey(day))));
  }

  const successfulDays = days.filter((day) => day.status === "success");
  const archivedDays = successfulDays.filter((day) => day.object_name !== null);
  const failedDays = days.filter((day) => day.status === "failed");
  const runningDays = days.filter((day) => day.status === "running");
  const archivedDocuments = successfulDays.reduce((total, day) => total + (day.document_count ?? 0), 0);
  const archiveBytes = successfulDays.reduce((total, day) => total + (day.archive_bytes ?? 0), 0);
  const latestRun = [...days]
    .filter((day) => day.started_at !== null)
    .sort((left, right) => (right.started_at ?? "").localeCompare(left.started_at ?? ""))[0] ?? null;
  const latestSuccessDay = successfulDays.at(-1)?.day ?? null;
  const lagDays = latestSuccessDay
    ? Math.max(0, Math.floor((window.to.getTime() - new Date(`${latestSuccessDay}T00:00:00Z`).getTime()) / (24 * 60 * 60 * 1_000)))
    : window.days;

  return {
    expected_days: window.days,
    successful_days: successfulDays.length,
    archived_days: archivedDays.length,
    empty_days: successfulDays.filter((day) => day.document_count === 0).length,
    failed_days: failedDays.length,
    running_days: runningDays.length,
    missing_days: days.filter((day) => day.status === "missing").length,
    archived_documents: archivedDocuments,
    archive_bytes: archiveBytes,
    latest_success_day: latestSuccessDay,
    lag_days: lagDays,
    last_started_at: latestDate(days, "started_at"),
    last_completed_at: latestDate(days, "completed_at"),
    latest_run_status: latestRun?.status ?? null,
  };
}

export function buildBackupTargetExceptions(
  documents: Document[],
  targetId: BackupTargetId,
  window = getHardwareBackupWindow(),
): BackupException[] {
  const manifests = new Map<string, HardwareBackupDay>();
  for (const document of documents) {
    if (manifestTargetId(document) !== targetId) continue;
    const day = manifestDay(document);
    if (day) manifests.set(day.day, day);
  }

  const exceptions: BackupException[] = [];
  for (let day = window.from; day <= window.to; day = addUtcDays(day, 1)) {
    const manifest = expectedDay(day, manifests.get(dayKey(day)));
    if (manifest.status === "success") continue;
    exceptions.push({
      target_id: targetId,
      day: manifest.day,
      status: manifest.status,
      detail: manifest.status === "failed"
        ? manifest.error ?? "Manifest marked failed without an error detail."
        : manifest.status === "running"
          ? "Manifest is still being written by the Pi worker."
          : "No manifest has been recorded for this eligible UTC day.",
      document_count: manifest.document_count,
      archive_bytes: manifest.archive_bytes,
      started_at: manifest.started_at,
      completed_at: manifest.completed_at,
      action_supported: targetId === HARDWARE_COLLECTION,
    });
  }
  return exceptions;
}

function requestDurationSeconds(request: HardwareBackupRequestView, now = new Date()): number | null {
  const start = asDate(request.started_at ?? request.created_at);
  if (!start) return null;
  const end = asDate(request.completed_at) ?? (request.status === "pending" || request.status === "running" ? now : null);
  if (!end) return null;
  return Math.max(0, Math.floor((end.getTime() - start.getTime()) / 1_000));
}

function backupActivityView(document: Document, now = new Date()): BackupActivityEntry | null {
  const request = requestView(document);
  if (!request) return null;
  return { ...request, duration_seconds: requestDurationSeconds(request, now) };
}

function workerStatus(
  documents: Document[],
  targetCount: number,
  attentionCount: number,
  now = new Date(),
): BackupWorkerStatus {
  const reports = documents
    .map((document) => ({
      seenAt: asDate(document.last_seen_at),
      mode: document.mode === "control" || document.mode === "scheduled" ? document.mode : null,
      pollSeconds: numberValue(document.poll_seconds),
    }))
    .filter((report): report is { seenAt: Date; mode: "control" | "scheduled" | null; pollSeconds: number | null } => report.seenAt !== null);
  const latest = reports.sort((left, right) => right.seenAt.getTime() - left.seenAt.getTime())[0];
  if (!latest) {
    return {
      state: "unknown",
      mode: null,
      poll_seconds: null,
      last_seen_at: null,
      heartbeat_age_seconds: null,
      target_count: targetCount,
      attention_count: attentionCount,
    };
  }

  const ageSeconds = Math.max(0, Math.floor((now.getTime() - latest.seenAt.getTime()) / 1_000));
  const pollSeconds = latest.pollSeconds ?? BACKUP_CONTROL_POLL_SECONDS;
  const healthyAfterSeconds = Math.max(BACKUP_HEALTHY_AFTER_SECONDS, pollSeconds * 6);
  const staleAfterSeconds = Math.max(BACKUP_STALE_AFTER_SECONDS, pollSeconds * 120);
  const state = latest.mode === "scheduled"
    ? "scheduled"
    : ageSeconds <= healthyAfterSeconds
      ? "healthy"
      : ageSeconds <= staleAfterSeconds
        ? "stale"
        : "offline";
  return {
    state,
    mode: latest.mode,
    poll_seconds: pollSeconds,
    last_seen_at: latest.seenAt.toISOString(),
    heartbeat_age_seconds: ageSeconds,
    target_count: targetCount,
    attention_count: attentionCount,
  };
}

function backupPolicy(window: ReturnType<typeof getHardwareBackupWindow>): BackupPolicy {
  return {
    lookback_days: LOOKBACK_DAYS,
    safety_days: SAFETY_DAYS,
    eligible_days: window.days,
    schedule: "Daily systemd timer",
    archive_format: "gzip Extended JSON Lines",
    destination_visibility: "Private Backblaze B2",
    sensitive_target_policy: "Threat events require explicit opt-in",
  };
}

function restoreReadinessView(document: Document | null): BackupRestoreReadiness {
  const status = document?.status === "verified" || document?.status === "failed" || document?.status === "not_tested" || document?.status === "unavailable"
    ? document.status
    : null;
  if (!status) {
    return {
      status: "not_tested",
      last_verified_at: null,
      detail: "No restore rehearsal has been recorded yet; the read-only restore path remains documented but unverified.",
      source: "Read-only restore operator path",
    };
  }
  return {
    status,
    last_verified_at: dateValue(document?.last_verified_at ?? document?.verified_at),
    detail: textValue(document?.detail) ?? "Restore verification record has no detail.",
    source: textValue(document?.source, 120) ?? "Read-only restore operator path",
  };
}

export async function getHardwareBackupStatus(): Promise<HardwareBackupStatus> {
  const window = getHardwareBackupWindow();
  const query: Document = {
    collection: HARDWARE_COLLECTION,
    day_start: { $gte: window.from, $lte: window.to },
  };
  const client = await getMongoClient();
  const database = client.db(getMongoDatabaseName());
  const [documents, latestRequest, storageSnapshot] = await Promise.all([
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
    database.collection(STORAGE_SNAPSHOT_COLLECTION).findOne(
      { source: HARDWARE_COLLECTION },
      {
        projection: { source: 1, bucket: 1, storage_bytes: 1, file_versions: 1, checked_at: 1 },
        sort: { checked_at: -1 },
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
    storage: storageSnapshotView(storageSnapshot),
  };
}

export async function getBackupTargetOverview(): Promise<BackupTargetOverview> {
  const client = await getMongoClient();
  const database = client.db(getMongoDatabaseName());
  const window = getHardwareBackupWindow();
  const now = new Date();
  const targetIds = BACKUP_TARGET_CATALOG.map((target) => target.target_id);
  const [statusDocuments, manifestDocuments, requestDocuments, storageDocuments, restoreDocument] = await Promise.all([
    database.collection(TARGET_STATUS_COLLECTION).find({
      target_id: { $in: targetIds },
      enabled: true,
    }).project({ target_id: 1, enabled: 1, last_seen_at: 1, mode: 1, poll_seconds: 1 }).toArray(),
    database.collection(BACKUP_COLLECTION).find({
      day_start: { $gte: window.from, $lte: window.to },
      $or: [
        { target_id: { $in: targetIds } },
        { collection: { $in: targetIds } },
      ],
    }).project({
      target_id: 1,
      collection: 1,
      day_start: 1,
      status: 1,
      document_count: 1,
      archive_bytes: 1,
      started_at: 1,
      completed_at: 1,
      object_name: 1,
      error: 1,
    }).sort({ day_start: 1 }).limit(MAX_MANIFESTS * BACKUP_TARGET_CATALOG.length).toArray(),
    database.collection(REQUEST_COLLECTION).find({ source: { $in: targetIds } }).project({
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
    }).sort({ created_at: -1 }).limit(10).toArray(),
    database.collection(STORAGE_SNAPSHOT_COLLECTION).find({}).project({
      source: 1,
      bucket: 1,
      storage_bytes: 1,
      file_versions: 1,
      checked_at: 1,
    }).sort({ checked_at: -1 }).limit(20).toArray(),
    database.collection(RESTORE_VERIFICATION_COLLECTION).findOne({}, {
      projection: { status: 1, verified_at: 1, last_verified_at: 1, detail: 1, source: 1 },
      sort: { verified_at: -1, last_verified_at: -1, created_at: -1 },
    }),
  ]);

  const liveTargets = new Map<string, Document>();
  for (const document of statusDocuments) {
    if (typeof document.target_id === "string") liveTargets.set(document.target_id, document);
  }

  const targets = BACKUP_TARGET_CATALOG.map((target) => {
    const statusDocument = liveTargets.get(target.target_id);
    const coverage = buildBackupTargetCoverage(manifestDocuments, target.target_id, window);
    const fallbackHardwareActivation = target.target_id === "hardware_metrics_1m" && !statusDocument && coverage.successful_days > 0;
    const active = Boolean(statusDocument?.enabled) || fallbackHardwareActivation;
    return {
      target_id: target.target_id,
      state: (active ? "active" : "planned") as BackupTargetState,
      collections: [...target.collections],
      sensitive: target.sensitive,
      last_seen_at: dateValue(statusDocument?.last_seen_at),
      last_completed_at: coverage.last_completed_at,
      coverage,
    };
  });

  const activeCount = targets.filter((target) => target.state === "active").length;
  const allExceptions = targets
    .filter((target) => target.state === "active")
    .flatMap((target) => buildBackupTargetExceptions(manifestDocuments, target.target_id, window))
    .sort((left, right) => {
      const priority = { failed: 0, running: 1, missing: 2 };
      return priority[left.status] - priority[right.status] || right.day.localeCompare(left.day);
    });
  const activity = requestDocuments
    .map((document) => backupActivityView(document, now))
    .filter((request): request is BackupActivityEntry => request !== null);
  const destination = storageDocuments
    .map((document) => destinationSnapshotView(document, now))
    .find((snapshot): snapshot is BackupDestinationStatus => snapshot !== null) ?? null;

  return {
    generated_at: now.toISOString(),
    active_count: activeCount,
    planned_count: targets.length - activeCount,
    worker: workerStatus(statusDocuments, activeCount, allExceptions.length, now),
    destination,
    policy: backupPolicy(window),
    restore: restoreReadinessView(restoreDocument),
    exceptions: allExceptions.slice(0, 12),
    activity,
    targets,
  };
}
