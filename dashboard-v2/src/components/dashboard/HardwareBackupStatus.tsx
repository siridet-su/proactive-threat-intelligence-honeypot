"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowUpRight,
  CalendarDays,
  CheckCircle2,
  CircleDashed,
  Cloud,
  Clock3,
  Database,
  HardDrive,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  TimerReset,
  XCircle,
  type LucideIcon,
} from "lucide-react";

import { RegionState } from "@/components/ui/RegionState";
import { cn } from "@/lib/utils";
import {
  isHardwareBackupStatus,
  type HardwareBackupDay,
  type HardwareBackupRequestAction,
  type HardwareBackupRequestView,
  type HardwareBackupStorageStatus,
  type HardwareBackupStatus as HardwareBackupStatusData,
} from "@/lib/dashboardTypes";

type BackupState = "healthy" | "partial" | "attention" | "running" | "not_started";
type DayVisualStatus = HardwareBackupDay["status"] | "empty";
type StatTone = "primary" | "success" | "info" | "warning" | "neutral";

const toneClasses: Record<StatTone, string> = {
  primary: "border-primary-border bg-primary-subtle text-primary",
  success: "border-success-border bg-success-subtle text-success",
  info: "border-info-border bg-info-subtle text-info",
  warning: "border-warning-border bg-warning-subtle text-warning",
  neutral: "border-border bg-surface-subtle text-text-muted",
};

const dayClasses: Record<DayVisualStatus, string> = {
  success: "border-success-border bg-success-subtle text-success hover:border-success hover:shadow-[0_0_0_3px_color-mix(in_srgb,var(--success)_10%,transparent)]",
  empty: "border-border bg-surface text-text-subtle hover:border-border-strong hover:bg-surface-hover",
  running: "border-info-border bg-info-subtle text-info hover:border-info",
  failed: "border-danger-border bg-danger-subtle text-danger hover:border-danger",
  missing: "border-warning-border bg-warning-subtle text-warning hover:border-warning",
};

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

function dayLabel(day: HardwareBackupDay) {
  if (day.status === "missing") return `${day.day}: no manifest recorded`;
  if (day.status === "running") return `${day.day}: backup in progress`;
  if (day.status === "failed") return `${day.day}: backup failed${day.error ? ` — ${day.error}` : ""}`;
  if (day.document_count === 0) return `${day.day}: completed, no rollup documents`;
  return `${day.day}: completed, ${formatNumber(day.document_count)} documents, ${formatBytes(day.archive_bytes)}`;
}

function visualDayStatus(day: HardwareBackupDay): DayVisualStatus {
  if (day.status === "success" && day.document_count === 0) return "empty";
  return day.status;
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
      description: "All expected days archived",
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
  const coveragePercent = data && data.summary.expected_days > 0
    ? Math.min(100, Math.round((data.summary.successful_days / data.summary.expected_days) * 100))
    : 0;
  const StatusIcon = presentation?.Icon ?? CircleDashed;
  const activeRequest = request?.status === "pending" || request?.status === "running";
  const actionDisabled = loading || refreshing || actionLoading !== null || activeRequest;

  return (
    <motion.section
      initial={reduceMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="relative overflow-hidden rounded-[1.25rem] border border-border bg-surface shadow-[0_18px_55px_color-mix(in_srgb,var(--text)_8%,transparent)]"
      aria-labelledby="hardware-backup-title"
    >
      <div className="pointer-events-none absolute -right-24 -top-32 h-80 w-80 rounded-full bg-primary/10 blur-3xl" aria-hidden="true" />
      <div className="pointer-events-none absolute -bottom-40 left-1/3 h-72 w-72 rounded-full bg-info/5 blur-3xl" aria-hidden="true" />

      <header className="relative flex flex-col gap-4 border-b border-border px-5 py-5 sm:px-6 sm:py-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-3.5">
          <div className="relative grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-primary-border bg-primary-subtle text-primary shadow-[0_0_0_5px_color-mix(in_srgb,var(--primary)_6%,transparent)]">
            <Archive className="h-5 w-5" aria-hidden="true" />
            <span className="absolute -bottom-1 -right-1 h-3 w-3 rounded-full border-2 border-surface bg-success" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-primary">Hardware archive</span>
              {presentation && (
                <span className={`ui-badge text-[10px] ${presentation.className}`} aria-live="polite">
                  <StatusIcon className="h-3 w-3" aria-hidden="true" />
                  {presentation.label}
                </span>
              )}
            </div>
            <h2 id="hardware-backup-title" className="mt-1 text-xl font-semibold tracking-tight sm:text-2xl">Rollup backup</h2>
            <p className="mt-0.5 text-xs text-text-muted">`hardware_metrics_1m` → private Backblaze B2</p>
          </div>
        </div>
        <div className="flex items-center justify-between gap-3 lg:justify-end">
          <div className="text-left lg:text-right">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-subtle">Last sync</p>
            <p className="mt-0.5 font-mono text-xs tabular-nums text-text-muted">{formatDateTime(data?.generated_at ?? null)}</p>
          </div>
          <button type="button" onClick={refresh} disabled={loading || refreshing} className="ui-button h-10 min-h-10 w-10 p-0" title="Refresh backup status" aria-label="Refresh backup status">
            <RefreshCw className={`h-4 w-4 ${refreshing ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
          </button>
        </div>
      </header>

      {/* Scanning Laser Bar when loading, refreshing, or queuing an action */}
      <div className="h-0.5 w-full bg-border/40 overflow-hidden relative">
        {(loading || refreshing || actionLoading !== null) && (
          <div
            className="absolute inset-y-0 w-56 bg-gradient-to-r from-transparent via-primary to-transparent"
            style={{
              animation: "pti-laser-scan 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
            }}
          />
        )}
      </div>

      <div className="relative grid xl:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="min-w-0 p-5 sm:p-6">
          {loading && !data ? (
            <BackupSkeleton />
          ) : error && !data ? (
            <RegionState kind="error" title="Backup status unavailable" description={`${error}. Retry when the dashboard can reach MongoDB.`} />
          ) : data && presentation ? (
            <div className={cn("space-y-6 relative transition-opacity duration-200", refreshing && "opacity-50")}>
              {refreshing && (
                <div className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center">
                  <div className="flex items-center gap-2.5 rounded-xl border border-primary-border bg-surface-raised/95 px-3.5 py-2 shadow-xl backdrop-blur-xs">
                    <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
                    <span className="font-mono text-xs font-semibold text-text">Syncing backup manifests…</span>
                  </div>
                </div>
              )}
              {error && <p role="status" className="rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-xs text-warning">Showing the last successful result · {error}</p>}
              <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-4">
                <BackupStat icon={CalendarDays} label="Coverage" value={`${coveragePercent}%`} detail={`${data.summary.successful_days} / ${data.summary.expected_days} days`} tone={coveragePercent === 100 ? "success" : coveragePercent > 70 ? "warning" : "neutral"} />
                <BackupStat icon={Database} label="Archived records" value={formatNumber(data.summary.archived_documents)} detail={`${formatBytes(data.summary.archive_bytes)} compressed`} tone="info" />
                <BackupStat icon={HardDrive} label="Latest archive" value={formatDay(data.summary.latest_success_day)} detail={presentation.description} tone={presentation.state === "healthy" ? "success" : "warning"} />
                <BackupStat icon={Clock3} label="Last completed" value={formatDateTime(data.summary.last_completed_at)} detail={`Window ends ${formatDay(data.expected_window.to.slice(0, 10))}`} tone="primary" />
              </div>

              <CoverageMap data={data} coveragePercent={coveragePercent} reduceMotion={Boolean(reduceMotion)} />
            </div>
          ) : (
            <RegionState kind="empty" title="No backup status yet" description="The worker has not written a manifest." />
          )}
        </div>

        <aside className="border-t border-border bg-surface-subtle/55 p-5 sm:p-6 xl:border-l xl:border-t-0" aria-label="Backup controls and destination">
          {data ? (
            <div className="space-y-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-text-subtle">Control room</p>
                  <h3 className="mt-1 text-sm font-semibold">Pi worker</h3>
                </div>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-success-border bg-success-subtle px-2 py-1 text-[10px] font-semibold text-success">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-success" aria-hidden="true" />
                  Connected
                </span>
              </div>

              {actionError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle px-3 py-2 text-xs leading-5 text-danger">{actionError}</p>}

              {data.can_control ? (
                <div className="space-y-2">
                  <button type="button" onClick={() => runAction("run_missing")} disabled={actionDisabled} className="ui-button ui-button-primary min-h-11 w-full justify-between rounded-xl px-3.5 text-xs">
                    <span className="flex items-center gap-2">
                      {actionLoading === "run_missing" ? (
                        <RefreshCw className="h-4 w-4 animate-spin text-surface" aria-hidden="true" />
                      ) : (
                        <Play className="h-4 w-4" aria-hidden="true" />
                      )}
                      {actionLoading === "run_missing" ? "Queueing missing days…" : "Run missing days"}
                    </span>
                    <ArrowUpRight className="h-3.5 w-3.5 opacity-70" aria-hidden="true" />
                  </button>
                  <button type="button" onClick={() => runAction("retry_failed")} disabled={actionDisabled} className="ui-button min-h-10 w-full justify-between rounded-xl px-3.5 text-xs">
                    <span className="flex items-center gap-2">
                      {actionLoading === "retry_failed" ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
                      ) : (
                        <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      {actionLoading === "retry_failed" ? "Queueing retry…" : "Retry failed days"}
                    </span>
                    <span className="font-mono text-[10px] text-text-subtle">AUDITED</span>
                  </button>
                </div>
              ) : (
                <div className="rounded-xl border border-border bg-surface px-3.5 py-3 text-xs text-text-muted">
                  <div className="flex items-center gap-2 font-medium text-text"><ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />Read-only mode</div>
                  <p className="mt-1.5 text-[11px] leading-5 text-text-subtle">Admin access is required for Pi actions.</p>
                </div>
              )}

              <AnimatePresence initial={false} mode="popLayout">
                {request && <BackupRequestProgress request={request} reduceMotion={Boolean(reduceMotion)} />}
              </AnimatePresence>

              <CloudStorageSummary storage={data.storage} />

              <div className="grid grid-cols-2 gap-2 border-t border-border pt-4">
                <MiniFact icon={TimerReset} label="Schedule" value="03:30 daily" />
                <MiniFact icon={CalendarDays} label="Lookback" value="30 days" />
                <MiniFact icon={ShieldCheck} label="Safety hold" value="2 days" />
                <MiniFact icon={Server} label="Source" value="Pi local" />
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

const BACKUP_STAT_SKELETONS = [
  { icon: CalendarDays, label: "Coverage", placeholder: "--%", detail: "30 expected days", tone: "neutral" as const },
  { icon: Database, label: "Archived records", placeholder: "---", detail: "Compressed archives", tone: "info" as const },
  { icon: HardDrive, label: "Latest archive", placeholder: "---", detail: "Manifest status", tone: "neutral" as const },
  { icon: Clock3, label: "Last completed", placeholder: "---", detail: "Daily backup window", tone: "primary" as const },
];

function BackupSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true" aria-label="Loading hardware backup status">
      {/* 4 Realistic Stat Cards */}
      <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-4">
        {BACKUP_STAT_SKELETONS.map((item) => (
          <div
            key={item.label}
            className="group min-w-0 rounded-xl border border-border bg-surface p-3.5 shadow-sm"
          >
            <div className="flex items-start justify-between gap-2">
              <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${toneClasses[item.tone]}`}>
                <item.icon className="h-4 w-4" aria-hidden="true" />
              </span>
              <span className="h-1.5 w-1.5 rounded-full bg-border-strong animate-pulse" />
            </div>
            <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.12em] text-text-subtle">{item.label}</p>
            <p className="mt-1 truncate font-mono text-lg font-semibold leading-6 tracking-tight text-text">
              <span className="opacity-60">{item.placeholder}</span>
            </p>
            <p className="mt-1 truncate text-[11px] text-text-muted">{item.detail}</p>
          </div>
        ))}
      </div>

      {/* Realistic Coverage Map Skeleton */}
      <div className="rounded-xl border border-border bg-surface-subtle/60 p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <CalendarDays className="h-4 w-4 text-primary" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-text">30-day lookback coverage</h3>
            </div>
            <p className="text-xs text-text-muted">Daily Pi backups verified against MongoDB and Backblaze B2.</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xl font-bold leading-none text-text-subtle/80 animate-pulse">--%</span>
            <span className="text-xs text-text-subtle">coverage</span>
          </div>
        </div>

        {/* 30-day calendar lookback chips */}
        <div className="mt-5 grid grid-cols-7 gap-1.5 sm:grid-cols-10 md:grid-cols-12 lg:grid-cols-[repeat(15,minmax(0,1fr))]">
          {Array.from({ length: 30 }, (_, index) => (
            <div
              key={index}
              className="flex min-h-[3.15rem] flex-col items-center justify-center rounded-lg border border-border/70 bg-surface p-1.5"
            >
              <span className="text-[9px] font-medium uppercase tracking-wider text-text-subtle/70">Day</span>
              <span className="font-mono text-xs font-semibold text-text-muted">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="mt-1 h-1.5 w-1.5 rounded-full bg-border-strong animate-pulse" />
            </div>
          ))}
        </div>

        {/* Coverage Legend */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-3 text-[11px] text-text-subtle">
          <div className="flex flex-wrap items-center gap-3">
            <LegendDot className="bg-success" label="Success" />
            <LegendDot className="border border-border bg-surface" label="No records" />
            <LegendDot className="bg-info" label="In progress" />
            <LegendDot className="bg-warning" label="Missing" />
            <LegendDot className="bg-danger" label="Failed" />
          </div>
          <div className="h-1.5 min-w-32 flex-1 rounded-full bg-surface-hover sm:max-w-48 overflow-hidden">
            <div className="h-full w-24 bg-primary/30 animate-pulse rounded-full" />
          </div>
        </div>
      </div>
    </div>
  );
}

function PiControlSkeleton() {
  return (
    <div className="space-y-5" aria-hidden="true">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-text-subtle">Control room</p>
          <h3 className="mt-1 text-sm font-semibold">Pi worker</h3>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-info-border bg-info-subtle px-2 py-1 text-[10px] font-semibold text-info">
          <RefreshCw className="h-3 w-3 animate-spin text-info" aria-hidden="true" />
          Connecting
        </span>
      </div>

      <div className="space-y-2">
        <button
          type="button"
          disabled
          className="ui-button ui-button-primary min-h-11 w-full justify-between rounded-xl px-3.5 text-xs opacity-60 cursor-not-allowed"
        >
          <span className="flex items-center gap-2">
            <Play className="h-4 w-4" aria-hidden="true" />
            Run missing days
          </span>
          <ArrowUpRight className="h-3.5 w-3.5 opacity-70" aria-hidden="true" />
        </button>
        <button
          type="button"
          disabled
          className="ui-button min-h-10 w-full justify-between rounded-xl px-3.5 text-xs opacity-60 cursor-not-allowed"
        >
          <span className="flex items-center gap-2">
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            Retry failed days
          </span>
          <span className="font-mono text-[10px] text-text-subtle">AUDITED</span>
        </button>
      </div>

      <div className="rounded-xl border border-border bg-surface p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="grid h-8 w-8 place-items-center rounded-lg border border-info-border bg-info-subtle text-info">
              <Cloud className="h-4 w-4" aria-hidden="true" />
            </span>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-text-subtle">Destination</p>
              <h3 className="mt-0.5 text-xs font-semibold">Backblaze B2</h3>
            </div>
          </div>
          <span className="h-2 w-2 rounded-full bg-border-strong animate-pulse" />
        </div>
        <p className="mt-4 font-mono text-2xl font-semibold tracking-tight text-text-subtle/80 animate-pulse">
          ---.- KiB
        </p>
        <p className="mt-1 text-[11px] text-text-muted">Waiting for cloud storage snapshot…</p>
        <div className="mt-4 flex items-center justify-between gap-2 border-t border-border pt-3 text-[10px] text-text-subtle">
          <span className="font-mono">pti-backups</span>
          <span>Checked —</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 border-t border-border pt-4">
        <MiniFact icon={TimerReset} label="Schedule" value="03:30 daily" />
        <MiniFact icon={CalendarDays} label="Lookback" value="30 days" />
        <MiniFact icon={ShieldCheck} label="Safety hold" value="2 days" />
        <MiniFact icon={Server} label="Source" value="Pi local" />
      </div>
    </div>
  );
}

function CoverageMap({ data, coveragePercent, reduceMotion }: { data: HardwareBackupStatusData; coveragePercent: number; reduceMotion: boolean }) {
  return (
    <section className="rounded-xl border border-border bg-surface-subtle/60 p-4 sm:p-5" aria-labelledby="backup-coverage-title">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
            <h3 id="backup-coverage-title" className="text-sm font-semibold">Coverage map</h3>
          </div>
          <p className="mt-1 text-xs text-text-muted">{formatDay(data.expected_window.from.slice(0, 10))} → {formatDay(data.expected_window.to.slice(0, 10))} · UTC days</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-2xl font-semibold tracking-tight text-text">{coveragePercent}%</span>
          <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-subtle">covered</span>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-7 gap-1.5 sm:grid-cols-10 md:grid-cols-12 lg:grid-cols-[repeat(15,minmax(0,1fr))]" role="list" aria-label="Hardware backup days">
        {data.days.map((day) => {
          const status = visualDayStatus(day);
          return (
            <button
              key={day.day}
              type="button"
              role="listitem"
              aria-label={dayLabel(day)}
              title={dayLabel(day)}
              className={`group relative flex min-h-[3.15rem] flex-col items-center justify-center rounded-lg border text-xs font-mono transition-all duration-200 hover:-translate-y-0.5 focus-visible:z-10 ${dayClasses[status]}`}
            >
              <span className="text-[10px] opacity-65">{day.day.slice(5, 7)}</span>
              <span className="text-sm font-semibold">{day.day.slice(8, 10)}</span>
              <span className={`absolute bottom-1 h-1 w-1 rounded-full ${status === "success" ? "bg-success" : status === "failed" ? "bg-danger" : status === "missing" ? "bg-warning" : status === "running" ? "bg-info" : "bg-text-subtle"}`} aria-hidden="true" />
            </button>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[10px] text-text-subtle" aria-label="Backup status legend">
          <LegendDot className="bg-success" label="Archived" />
          <LegendDot className="bg-text-subtle" label="Empty" />
          <LegendDot className="bg-warning" label="Missing" />
          <LegendDot className="bg-danger" label="Failed" />
        </div>
        <div className="h-1.5 min-w-32 flex-1 overflow-hidden rounded-full bg-surface-hover sm:max-w-48" aria-label={`Backup coverage ${coveragePercent}%`}>
          <motion.div
            initial={{ width: reduceMotion ? `${coveragePercent}%` : 0 }}
            animate={{ width: `${coveragePercent}%` }}
            transition={{ duration: reduceMotion ? 0 : 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="h-full rounded-full bg-gradient-to-r from-primary to-success"
          />
        </div>
      </div>
    </section>
  );
}

function CloudStorageSummary({ storage }: { storage: HardwareBackupStorageStatus | null }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-info-border bg-info-subtle text-info"><Cloud className="h-4 w-4" aria-hidden="true" /></span>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-text-subtle">Destination</p>
            <h3 className="mt-0.5 text-xs font-semibold">Backblaze B2</h3>
          </div>
        </div>
        <span className={`h-2 w-2 rounded-full ${storage ? "bg-success shadow-[0_0_0_4px_color-mix(in_srgb,var(--success)_12%,transparent)]" : "bg-text-subtle"}`} aria-label={storage ? "Storage reported" : "Storage not reported"} />
      </div>
      {storage ? (
        <>
          <p className="mt-5 font-mono text-3xl font-semibold tracking-tight text-text">{formatBytes(storage.storage_bytes)}</p>
          <p className="mt-1 text-[11px] text-text-muted">{formatNumber(storage.file_versions)} file versions · all retained objects</p>
          <div className="mt-4 flex items-center justify-between gap-2 border-t border-border pt-3 text-[10px] text-text-subtle">
            <span className="max-w-[10rem] truncate font-mono" title={storage.bucket}>{storage.bucket}</span>
            <span>Checked {formatDateTime(storage.checked_at)}</span>
          </div>
        </>
      ) : (
        <p className="mt-4 rounded-lg border border-border bg-surface-subtle px-3 py-2.5 text-[11px] leading-5 text-text-subtle">Waiting for the first storage snapshot.</p>
      )}
    </div>
  );
}

function BackupRequestProgress({ request, reduceMotion }: { request: HardwareBackupRequestView; reduceMotion: boolean }) {
  const isActive = request.status === "pending" || request.status === "running";
  const statusClassName = request.status === "success"
    ? "border-success-border bg-success-subtle text-success"
    : request.status === "failed"
      ? "border-danger-border bg-danger-subtle text-danger"
      : "border-info-border bg-info-subtle text-info";
  const percent = Math.min(100, Math.max(0, request.progress.percent));
  const StatusIcon = request.status === "success" ? CheckCircle2 : request.status === "failed" ? XCircle : Clock3;

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
            <h3 className="truncate text-xs font-semibold text-text">{actionLabel(request.action)}</h3>
            <span className={`ui-badge text-[10px] ${statusClassName}`}>{requestStatusLabel(request)}</span>
          </div>
          <p className="mt-1 text-[10px] text-text-subtle">{isActive ? "Auto-refreshing every 5 seconds" : formatDateTime(request.completed_at ?? request.created_at)}</p>
        </div>
        <span className="font-mono text-xl font-semibold leading-none text-text">{percent}%</span>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface" aria-label={`Backup request progress ${percent}%`}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percent}%` }}
          transition={{ duration: reduceMotion ? 0 : 0.5, ease: "easeOut" }}
          className={`h-full rounded-full ${request.status === "failed" ? "bg-danger" : request.status === "success" ? "bg-success" : "bg-info"}`}
        />
      </div>
      <div className="mt-2 flex flex-wrap justify-between gap-2 text-[10px] text-text-subtle">
        <span>{formatNumber(request.progress.completed_days)} / {formatNumber(request.progress.total_days)} days</span>
        <span>{request.progress.current_day ? formatDay(request.progress.current_day) : request.status === "success" ? "No days required" : "Waiting for Pi"}</span>
      </div>
      {request.error && <p className="mt-2 break-words text-[11px] leading-4 text-danger">{request.error}</p>}
    </motion.div>
  );
}

function BackupStat({ icon: Icon, label, value, detail, tone }: { icon: LucideIcon; label: string; value: string; detail: string; tone: StatTone }) {
  return (
    <motion.div
      whileHover={{ y: -2 }}
      transition={{ duration: 0.16 }}
      className="group min-w-0 rounded-xl border border-border bg-surface p-3.5 shadow-sm transition-colors duration-200 hover:border-border-strong hover:shadow-md"
    >
      <div className="flex items-start justify-between gap-2">
        <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${toneClasses[tone]}`}><Icon className="h-4 w-4" aria-hidden="true" /></span>
        <ArrowUpRight className="h-3.5 w-3.5 text-text-subtle opacity-0 transition-opacity duration-200 group-hover:opacity-100" aria-hidden="true" />
      </div>
      <p className="mt-3 text-[10px] font-bold uppercase tracking-[0.12em] text-text-subtle">{label}</p>
      <p className="mt-1 truncate font-mono text-lg font-semibold leading-6 tracking-tight text-text" title={value}>{value}</p>
      <p className="mt-1 truncate text-[11px] text-text-muted" title={detail}>{detail}</p>
    </motion.div>
  );
}

function MiniFact({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-2.5 py-2">
      <div className="flex items-center gap-1.5 text-[10px] text-text-subtle"><Icon className="h-3 w-3 text-primary" aria-hidden="true" />{label}</div>
      <p className="mt-1 font-mono text-[11px] font-medium text-text">{value}</p>
    </div>
  );
}

function LegendDot({ className, label }: { className: string; label: string }) {
  return <span className="inline-flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${className}`} aria-hidden="true" />{label}</span>;
}
