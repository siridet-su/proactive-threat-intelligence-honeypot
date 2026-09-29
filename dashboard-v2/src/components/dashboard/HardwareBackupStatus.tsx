"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Archive,
  ArrowUpRight,
  CalendarDays,
  CheckCircle2,
  CircleDashed,
  Cloud,
  Clock3,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  TimerReset,
  XCircle,
} from "lucide-react";

import { RegionState } from "@/components/ui/RegionState";
import { cn } from "@/lib/utils";
import {
  isHardwareBackupStatus,
  type HardwareBackupRequestAction,
  type HardwareBackupRequestView,
  type HardwareBackupStorageStatus,
  type HardwareBackupStatus as HardwareBackupStatusData,
} from "@/lib/dashboardTypes";

type BackupState = "healthy" | "partial" | "attention" | "running" | "not_started";

function formatNumber(value: number | null) {
  return value === null ? "—" : new Intl.NumberFormat().format(value);
}

function formatBytes(value: number | null) {
  if (value === null || !Number.isFinite(value)) return "—";
  if (value < 1_024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unitIndex = -1;
  while (amount >= 1_024 && unitIndex < units.length - 1) {
    amount /= 1_024;
    unitIndex += 1;
  }
  return `${amount.toFixed(amount >= 100 ? 0 : amount >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function formatDay(value: string | null) {
  if (!value) return "—";
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(date.getTime())
    ? date.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" })
    : "—";
}

function formatDateTime(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : "—";
}

function actionLabel(action: HardwareBackupRequestAction) {
  return action === "run_missing" ? "Run missing days" : "Retry failed days";
}

function requestStatusLabel(request: HardwareBackupRequestView) {
  if (request.status === "pending") return "Queued";
  if (request.status === "running") return "Running";
  if (request.status === "success") return "Completed";
  return "Failed";
}

function statePresentation(data: HardwareBackupStatusData) {
  const { summary } = data;
  if (summary.failed_days > 0) {
    return {
      state: "attention" as BackupState,
      label: "Needs attention",
      description: `${summary.failed_days} failed day${summary.failed_days === 1 ? "" : "s"}`,
      className: "border-danger-border bg-danger-subtle text-danger",
      Icon: AlertTriangle,
    };
  }
  if (summary.running_days > 0) {
    return {
      state: "running" as BackupState,
      label: "Backup in progress",
      description: "Pi worker is writing a manifest",
      className: "border-info-border bg-info-subtle text-info",
      Icon: Clock3,
    };
  }
  if (summary.missing_days > 0) {
    return {
      state: "partial" as BackupState,
      label: "Partial coverage",
      description: `${summary.missing_days} missing day${summary.missing_days === 1 ? "" : "s"}`,
      className: "border-warning-border bg-warning-subtle text-warning",
      Icon: AlertTriangle,
    };
  }
  if (summary.successful_days > 0) {
    return {
      state: "healthy" as BackupState,
      label: "Healthy",
      description: "All eligible days checked",
      className: "border-success-border bg-success-subtle text-success",
      Icon: CheckCircle2,
    };
  }
  return {
    state: "not_started" as BackupState,
    label: "Not started",
    description: "Waiting for first archive",
    className: "border-border bg-surface-subtle text-text-muted",
    Icon: Archive,
  };
}

export function HardwareBackupStatus() {
  const reduceMotion = useReducedMotion();
  const [data, setData] = useState<HardwareBackupStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [actionLoading, setActionLoading] = useState<HardwareBackupRequestAction | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/hardware/backup", { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        const payload: unknown = await response.json();
        if (!response.ok || !isHardwareBackupStatus(payload)) throw new Error("Hardware backup status is unavailable");
        setData(payload);
        setError(null);
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Hardware backup status is unavailable");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
          setRefreshing(false);
        }
      });

    return () => controller.abort();
  }, [reloadToken]);

  const request = data?.request;

  useEffect(() => {
    if (!request || (request.status !== "pending" && request.status !== "running")) return;
    const timer = window.setInterval(() => setReloadToken((current) => current + 1), 5_000);
    return () => window.clearInterval(timer);
  }, [request]);

  const refresh = () => {
    setRefreshing(true);
    setReloadToken((current) => current + 1);
  };

  const runAction = async (action: HardwareBackupRequestAction) => {
    setActionLoading(action);
    setActionError(null);
    try {
      const response = await fetch("/api/hardware/backup/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const message = payload && typeof payload === "object" && "error" in payload && typeof (payload as { error?: unknown }).error === "string"
          ? (payload as { error: string }).error
          : "Backup action could not be queued";
        throw new Error(message);
      }
      setRefreshing(true);
      setReloadToken((current) => current + 1);
    } catch (reason: unknown) {
      setActionError(reason instanceof Error ? reason.message : "Backup action could not be queued");
    } finally {
      setActionLoading(null);
    }
  };

  const presentation = useMemo(() => (data ? statePresentation(data) : null), [data]);
  const StatusIcon = presentation?.Icon ?? CircleDashed;
  const activeRequest = request?.status === "pending" || request?.status === "running";
  const actionDisabled = loading || refreshing || actionLoading !== null || activeRequest;

  return (
    <motion.section
      initial={reduceMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm"
      aria-labelledby="hardware-backup-title"
    >
      <header className="flex flex-col gap-3 border-b border-border px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div className="flex min-w-0 items-center gap-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary">
            <Archive className="h-4 w-4" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="hardware-backup-title" className="text-base font-semibold tracking-tight sm:text-lg">Hardware archive controls</h2>
              {presentation && (
                <span className={`ui-badge text-xs ${presentation.className}`} aria-live="polite">
                  <StatusIcon className="h-3 w-3" aria-hidden="true" />
                  {presentation.label}
                </span>
              )}
            </div>
            <p className="mt-0.5 truncate font-mono text-xs text-text-muted">{data?.collection ?? "hardware_metrics_1m"} <span className="font-sans text-text-subtle">→ Backblaze B2</span></p>
          </div>
        </div>
        <div className="flex items-center justify-between gap-3 lg:justify-end">
          <div className="text-xs text-text-muted sm:text-right">
            <span className="text-text-subtle">Updated </span>
            <time className="font-mono tabular-nums">{formatDateTime(data?.generated_at ?? null)}</time>
          </div>
          <button type="button" onClick={refresh} disabled={refreshing} className="ui-button h-9 min-h-9 w-9 p-0" title="Refresh backup status" aria-label="Refresh backup status">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
          </button>
        </div>
      </header>

      <div>
        <div className="min-w-0 p-4 sm:p-5">
          {loading && !data ? (
            <BackupSkeleton />
          ) : error && !data ? (
            <RegionState kind="error" title="Backup status unavailable" description={`${error}. Retry when the dashboard can reach MongoDB.`} />
          ) : data && presentation ? (
            <div className={cn("relative space-y-4 transition-opacity duration-200", refreshing && "opacity-60")}>
              {refreshing && (
                <div className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center">
                  <div className="flex items-center gap-2 rounded-lg border border-primary-border bg-surface-raised/95 px-3 py-2 shadow-lg backdrop-blur-xs">
                    <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
                    <span className="text-xs font-semibold text-text">Updating archive status…</span>
                  </div>
                </div>
              )}
              {error && <p role="status" className="rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-sm text-warning">Showing the last successful result · {error}</p>}
              <p className="text-sm text-text-muted">{presentation.description}. Daily coverage for all three sources is shown in the shared calendar above.</p>
            </div>
          ) : (
            <RegionState kind="empty" title="No backup status yet" description="The worker has not written a manifest." />
          )}
        </div>

        <aside className="border-t border-border bg-surface-subtle/35 p-4 sm:p-5" aria-label="Backup controls and destination">
          {data ? (
            <div className="grid gap-3 lg:grid-cols-3">
              <div className="space-y-3 rounded-xl border border-border bg-surface p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><Server className="h-4 w-4" aria-hidden="true" /></span>
                  <div>
                    <h3 className="text-sm font-semibold">Pi worker</h3>
                    <p className="text-xs text-text-subtle">On-device archive actions</p>
                  </div>
                </div>
                <span className={`ui-badge text-xs ${data.can_control ? "border-success-border bg-success-subtle text-success" : "border-border bg-surface text-text-subtle"}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${data.can_control ? "bg-success" : "bg-text-subtle"}`} aria-hidden="true" />
                  {data.can_control ? "Ready" : "Read-only"}
                </span>
              </div>

              {actionError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle px-3 py-2 text-sm leading-5 text-danger">{actionError}</p>}

              {data.can_control ? (
                <div className="grid gap-2">
                  <button type="button" onClick={() => runAction("run_missing")} disabled={actionDisabled} className="ui-button ui-button-primary min-h-10 w-full justify-between rounded-lg px-3 text-sm">
                    <span className="flex items-center gap-2">
                      {actionLoading === "run_missing" ? (
                        <RefreshCw className="h-4 w-4 animate-spin text-surface" aria-hidden="true" />
                      ) : (
                        <Play className="h-4 w-4" aria-hidden="true" />
                      )}
                      {actionLoading === "run_missing" ? "Queueing missing days…" : "Run missing days"}
                    </span>
                    <ArrowUpRight className="h-4 w-4 opacity-70" aria-hidden="true" />
                  </button>
                  <button type="button" onClick={() => runAction("retry_failed")} disabled={actionDisabled} className="ui-button min-h-10 w-full justify-between rounded-lg px-3 text-sm">
                    <span className="flex items-center gap-2">
                      {actionLoading === "retry_failed" ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
                      ) : (
                        <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      {actionLoading === "retry_failed" ? "Queueing retry…" : "Retry failed days"}
                    </span>
                    <span className="text-xs text-text-subtle">Audited</span>
                  </button>
                </div>
              ) : (
                <div className="rounded-lg border border-border bg-surface px-3 py-3 text-sm text-text-muted">
                  <div className="flex items-center gap-2 font-medium text-text"><ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />Read-only mode</div>
                  <p className="mt-1.5 text-xs leading-5 text-text-subtle">Admin access is required for Pi actions.</p>
                </div>
              )}

              </div>
              <div className="rounded-xl border border-border bg-surface p-4">
                <h3 className="mb-3 text-sm font-semibold">Latest request</h3>
                <AnimatePresence initial={false} mode="popLayout">
                  {request ? <BackupRequestProgress request={request} reduceMotion={Boolean(reduceMotion)} /> : <p className="text-sm text-text-muted">No dashboard request yet.</p>}
                </AnimatePresence>
              </div>
              <div className="rounded-xl border border-border bg-surface p-4">
                <CloudStorageSummary storage={data.storage} />
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-text-muted lg:col-span-3" aria-label="Backup schedule and retention">
                <span className="inline-flex items-center gap-1.5"><TimerReset className="h-3.5 w-3.5 text-primary" aria-hidden="true" />Daily · Asia/Bangkok</span>
                <span className="inline-flex items-center gap-1.5"><CalendarDays className="h-3.5 w-3.5 text-primary" aria-hidden="true" />29 eligible UTC days</span>
                <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-primary" aria-hidden="true" />2-day safety hold</span>
              </div>
            </div>
          ) : (
            <PiControlSkeleton />
          )}
        </aside>
      </div>
    </motion.section>
  );
}

function BackupSkeleton() {
  return <div className="h-5 w-48 animate-pulse rounded bg-surface-hover" aria-busy="true" aria-label="Loading hardware backup status" />;
}

function PiControlSkeleton() {
  return (
    <div className="space-y-4" aria-hidden="true">
      <div className="flex items-center gap-2"><RefreshCw className="h-4 w-4 animate-spin text-info" aria-hidden="true" /><h3 className="text-sm font-semibold">Connecting to Pi worker</h3></div>
      <div className="space-y-2">
        <div className="h-10 animate-pulse rounded-lg bg-surface-hover" />
        <div className="h-10 animate-pulse rounded-lg bg-surface-hover" />
      </div>
      <div className="border-t border-border pt-4">
        <div className="flex items-center gap-2"><Cloud className="h-4 w-4 text-info" aria-hidden="true" /><span className="text-sm font-medium">Backblaze B2</span></div>
        <div className="mt-3 h-7 w-32 animate-pulse rounded bg-surface-hover" />
        <div className="mt-2 h-3 w-full animate-pulse rounded bg-surface-subtle" />
      </div>
    </div>
  );
}

function CloudStorageSummary({ storage }: { storage: HardwareBackupStorageStatus | null }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Cloud className="h-4 w-4 text-info" aria-hidden="true" />
          <div>
            <h3 className="text-sm font-semibold">Backblaze B2</h3>
            <p className="text-xs text-text-subtle">Cloud destination</p>
          </div>
        </div>
        <span className={`h-2 w-2 rounded-full ${storage ? "bg-success" : "bg-text-subtle"}`} aria-label={storage ? "Storage reported" : "Storage not reported"} />
      </div>
      {storage ? (
        <>
          <p className="mt-3 font-mono text-2xl font-semibold tracking-tight text-text">{formatBytes(storage.storage_bytes)}</p>
          <p className="mt-1 text-xs text-text-muted">{formatNumber(storage.file_versions)} file versions</p>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-text-subtle">
            <span className="max-w-[10rem] truncate font-mono" title={storage.bucket}>{storage.bucket}</span>
            <span>Checked {formatDateTime(storage.checked_at)}</span>
          </div>
        </>
      ) : (
        <p className="mt-3 text-sm text-text-subtle">Waiting for the first storage snapshot.</p>
      )}
    </div>
  );
}

function BackupRequestProgress({ request, reduceMotion }: { request: HardwareBackupRequestView; reduceMotion: boolean }) {
  const isActive = request.status === "pending" || request.status === "running";
  const noEligibleDays = request.status === "success" && request.progress.total_days === 0;
  const statusClassName = noEligibleDays
    ? "border-border bg-surface text-text-muted"
    : request.status === "success"
    ? "border-success-border bg-success-subtle text-success"
    : request.status === "failed"
      ? "border-danger-border bg-danger-subtle text-danger"
      : "border-info-border bg-info-subtle text-info";
  const percent = Math.min(100, Math.max(0, request.progress.percent));
  const StatusIcon = noEligibleDays ? CircleDashed : request.status === "success" ? CheckCircle2 : request.status === "failed" ? XCircle : Clock3;

  return (
    <motion.div
      layout
      initial={reduceMotion ? false : { opacity: 0, height: 0, y: -8 }}
      animate={{ opacity: 1, height: "auto", y: 0 }}
      exit={reduceMotion ? { opacity: 0 } : { opacity: 0, height: 0, y: -8 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
      className="overflow-hidden rounded-xl border border-info-border bg-info-subtle/45 p-3.5"
      aria-live="polite"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <StatusIcon className="h-3.5 w-3.5 text-info" aria-hidden="true" />
            <h3 className="truncate text-sm font-semibold text-text">{actionLabel(request.action)}</h3>
            <span className={`ui-badge text-xs ${statusClassName}`}>{noEligibleDays ? "No eligible days" : requestStatusLabel(request)}</span>
          </div>
          <p className="mt-1 text-xs text-text-subtle">{isActive ? "Progress refreshes every 5 seconds" : formatDateTime(request.completed_at ?? request.created_at)}</p>
        </div>
        <span className="font-mono text-xl font-semibold leading-none text-text">{noEligibleDays ? "0 days" : `${percent}%`}</span>
      </div>
      {!noEligibleDays && <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface" aria-label={`Backup request progress ${percent}%`}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percent}%` }}
          transition={{ duration: reduceMotion ? 0 : 0.5, ease: "easeOut" }}
          className={`h-full rounded-full ${request.status === "failed" ? "bg-danger" : request.status === "success" ? "bg-success" : "bg-info"}`}
        />
      </div>}
      {noEligibleDays && <p className="mt-3 text-xs text-text-muted">No archive was created. The worker found no {request.action === "run_missing" ? "missing" : "failed"} days in the current backup window.</p>}
      {!noEligibleDays && <div className="mt-2 flex flex-wrap justify-between gap-2 text-xs text-text-subtle">
        <span>{formatNumber(request.progress.completed_days)} / {formatNumber(request.progress.total_days)} days</span>
        <span>{request.progress.current_day ? formatDay(request.progress.current_day) : request.status === "success" ? "No days required" : "Waiting for Pi"}</span>
      </div>}
      {request.error && <p className="mt-2 break-words text-sm leading-5 text-danger">{request.error}</p>}
    </motion.div>
  );
}
