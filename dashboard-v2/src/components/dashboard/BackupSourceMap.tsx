"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Archive,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Cloud,
  Database,
  FileWarning,
  FolderArchive,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TimerReset,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import {
  isBackupTargetOverview,
  type BackupTargetCoverage,
  type BackupTargetId,
  type BackupTargetOverview,
  type BackupTargetStatus,
} from "@/lib/dashboardTypes";

const SOURCE_CARDS: Array<{
  targetId: BackupTargetId;
  title: string;
  collection: string;
  icon: LucideIcon;
}> = [
  {
    targetId: "hardware_metrics_1m",
    title: "Hardware rollups",
    collection: "hardware_metrics_1m",
    icon: Archive,
  },
  {
    targetId: "threat_events",
    title: "Threat event history",
    collection: "events",
    icon: FolderArchive,
  },
  {
    targetId: "filesystem_audit",
    title: "Filesystem audit history",
    collection: "cwd_events + cwd_session_state",
    icon: Database,
  },
];

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
    ? date.toLocaleDateString([], { month: "short", day: "numeric", timeZone: "UTC" })
    : "—";
}

function formatDateTime(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : "—";
}

function formatAge(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return "just now";
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

function formatDuration(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${String(remainingSeconds).padStart(2, "0")}s`;
}

function targetLabel(targetId: BackupTargetId | string) {
  if (targetId === "hardware_metrics_1m") return "Hardware rollups";
  if (targetId === "threat_events") return "Threat events";
  if (targetId === "filesystem_audit") return "Filesystem audit";
  return targetId;
}

function workerPresentation(overview: BackupTargetOverview | null) {
  const worker = overview?.worker;
  if (!worker) return {
    label: "Checking worker",
    detail: "Waiting for the first backup status response.",
    className: "border-border bg-surface-subtle text-text-subtle",
    Icon: CircleDashed,
  };
  if (worker.state === "healthy") return {
    label: "Worker healthy",
    detail: `Heartbeat ${formatAge(worker.heartbeat_age_seconds)} · ${worker.target_count} active target${worker.target_count === 1 ? "" : "s"}`,
    className: "border-success-border bg-success-subtle text-success",
    Icon: CheckCircle2,
  };
  if (worker.state === "scheduled") return {
    label: "Scheduled worker",
    detail: `Last report ${formatAge(worker.heartbeat_age_seconds)} · status is reported per run`,
    className: "border-info-border bg-info-subtle text-info",
    Icon: Clock3,
  };
  if (worker.state === "stale") return {
    label: "Worker heartbeat stale",
    detail: `Last report ${formatAge(worker.heartbeat_age_seconds)} · inspect the Pi service`,
    className: "border-warning-border bg-warning-subtle text-warning",
    Icon: AlertTriangle,
  };
  if (worker.state === "offline") return {
    label: "Worker offline",
    detail: `No heartbeat for ${formatAge(worker.heartbeat_age_seconds)} · actions may remain queued`,
    className: "border-danger-border bg-danger-subtle text-danger",
    Icon: XCircle,
  };
  return {
    label: "Worker status unknown",
    detail: "No enabled Pi target has reported a heartbeat.",
    className: "border-border bg-surface-subtle text-text-subtle",
    Icon: CircleDashed,
  };
}

function activityPresentation(status: string) {
  if (status === "success") return { label: "Completed", className: "border-success-border bg-success-subtle text-success", Icon: CheckCircle2 };
  if (status === "failed") return { label: "Failed", className: "border-danger-border bg-danger-subtle text-danger", Icon: XCircle };
  if (status === "running") return { label: "Running", className: "border-info-border bg-info-subtle text-info", Icon: RefreshCw };
  return { label: "Queued", className: "border-warning-border bg-warning-subtle text-warning", Icon: Clock3 };
}

function exceptionPresentation(status: string) {
  if (status === "failed") return { label: "Failed", className: "border-danger-border bg-danger-subtle text-danger", Icon: XCircle };
  if (status === "running") return { label: "Running", className: "border-info-border bg-info-subtle text-info", Icon: RefreshCw };
  return { label: "Missing", className: "border-warning-border bg-warning-subtle text-warning", Icon: AlertTriangle };
}

function statePresentation(overview: BackupTargetOverview | null, targetId: BackupTargetId, loading: boolean) {
  const target = overview?.targets.find((item) => item.target_id === targetId);
  if (loading && !overview) {
    return { label: "Checking", className: "border-border bg-surface-subtle text-text-subtle", active: false };
  }
  if (target?.state === "active") {
    return { label: "Active", className: "border-success-border bg-success-subtle text-success", active: true };
  }
  return { label: "Planned", className: "border-border bg-surface-subtle text-text-subtle", active: false };
}

function coveragePresentation(target: BackupTargetStatus | undefined) {
  if (!target || target.state !== "active") {
    return {
      label: "Awaiting activation",
      detail: "Manifest coverage will appear after the Pi enables this target.",
      className: "text-text-subtle",
    };
  }

  const coverage = target.coverage;
  if (coverage.failed_days > 0) {
    return {
      label: `${coverage.failed_days} failed day${coverage.failed_days === 1 ? "" : "s"}`,
      detail: "Review the failed manifest before considering this archive complete.",
      className: "text-danger",
    };
  }
  if (coverage.running_days > 0) {
    return {
      label: "Backup in progress",
      detail: "The Pi is currently writing a manifest.",
      className: "text-info",
    };
  }
  if (coverage.missing_days > 0) {
    return {
      label: `${coverage.archived_days}/${coverage.expected_days} days archived`,
      detail: `${coverage.missing_days} day${coverage.missing_days === 1 ? "" : "s"} still have no manifest.`,
      className: "text-warning",
    };
  }
  if (coverage.archived_days === 0 && coverage.empty_days === coverage.successful_days && coverage.successful_days > 0) {
    return {
      label: "No eligible records",
      detail: `${coverage.successful_days}/${coverage.expected_days} days checked; records are still inside the safety window or absent.`,
      className: "text-info",
    };
  }
  if (coverage.archived_days < coverage.expected_days) {
    return {
      label: `${coverage.archived_days}/${coverage.expected_days} days archived`,
      detail: `${coverage.empty_days} day${coverage.empty_days === 1 ? "" : "s"} completed with no records.`,
      className: "text-info",
    };
  }
  return {
    label: "Fully archived",
    detail: `${coverage.archived_days}/${coverage.expected_days} eligible days have B2 objects.`,
    className: "text-success",
  };
}

export function BackupSourceMap() {
  const reduceMotion = useReducedMotion();
  const [overview, setOverview] = useState<BackupTargetOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const response = await fetch("/api/backup/targets", { cache: "no-store" });
        const payload: unknown = await response.json();
        if (!response.ok || !isBackupTargetOverview(payload)) throw new Error("Backup target overview is unavailable");
        if (disposed) return;
        setOverview(payload);
        setError(false);
      } catch {
        if (!disposed) setError(true);
      } finally {
        if (!disposed) setLoading(false);
      }
    };

    void load();
    const refreshTimer = window.setInterval(() => void load(), 30_000);
    return () => {
      disposed = true;
      window.clearInterval(refreshTimer);
    };
  }, []);

  const activeCount = overview?.active_count ?? 0;
  const plannedCount = overview?.planned_count ?? SOURCE_CARDS.length - activeCount;

  return (
    <motion.section
      initial={reduceMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: reduceMotion ? 0 : 0.08, ease: [0.22, 1, 0.36, 1] }}
      className="space-y-4"
      aria-labelledby="backup-sources-title"
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="backup-sources-title" className="text-lg font-semibold tracking-tight">Archive sources</h2>
          <p className="mt-1 text-sm text-text-muted">Compare backup coverage and data volume across collections.</p>
        </div>
        <span className="ui-badge w-fit text-xs" aria-live="polite">
          {error ? <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" /> : <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />}
          {error ? "Status unavailable" : `${activeCount} active · ${plannedCount} planned`}
        </span>
      </div>
      <BackupPosture overview={overview} loading={loading} />
      <section className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm" aria-labelledby="source-coverage-title">
        <div className="flex flex-col gap-2 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <div>
            <h3 id="source-coverage-title" className="text-sm font-semibold">30-day archive coverage</h3>
            <p className="mt-0.5 text-xs text-text-muted">A manifest check is shown separately from archived records.</p>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-text-muted" aria-label="Coverage status legend">
            <LegendDot className="bg-success" label="Archived" />
            <LegendDot className="bg-text-subtle/60" label="Empty" />
            <LegendDot className="bg-danger" label="Failed" />
            <LegendDot className="bg-info" label="Running" />
            <LegendDot className="bg-warning" label="Missing" />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] border-collapse text-left">
            <thead className="bg-surface-subtle/70 text-xs font-medium text-text-subtle">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium sm:px-5">Source</th>
                <th scope="col" className="px-3 py-2.5 font-medium">State</th>
                <th scope="col" className="w-[27%] px-3 py-2.5 font-medium">Coverage</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Archived data</th>
                <th scope="col" className="px-4 py-2.5 font-medium sm:px-5">Latest</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {SOURCE_CARDS.map(({ targetId, title, collection, icon: Icon }) => {
                const presentation = statePresentation(overview, targetId, loading);
                const target = overview?.targets.find((item) => item.target_id === targetId);
                const coverage = target?.state === "active" ? target.coverage : undefined;
                const coverageState = coveragePresentation(target);
                const checkedPercent = coverage && coverage.expected_days > 0
                  ? Math.round((coverage.archived_days / coverage.expected_days) * 100)
                  : 0;
                return (
                  <tr key={targetId} className="align-middle transition-colors hover:bg-surface-subtle/45">
                    <th scope="row" className="px-4 py-3 font-normal sm:px-5">
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><Icon className="h-4 w-4" aria-hidden="true" /></span>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-text">{title}</p>
                          <p className="mt-0.5 flex items-center gap-1 truncate font-mono text-xs text-text-muted" title={collection}>
                            {target?.sensitive && <LockKeyhole className="h-3 w-3 shrink-0 text-warning" aria-label="Sensitive target" />}
                            {collection}
                          </p>
                        </div>
                      </div>
                    </th>
                    <td className="px-3 py-3">
                      <span className={`ui-badge text-xs ${presentation.className}`}>
                        {loading && !overview && <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
                        {presentation.label}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="font-mono text-base font-semibold text-text">{coverage ? `${checkedPercent}%` : "—"}</span>
                        <span className={`text-xs ${coverageState.className}`}>{coverage ? `${coverage.archived_days}/${coverage.expected_days} days` : coverageState.label}</span>
                      </div>
                      <CoverageRail coverage={coverage} />
                      {coverage?.failed_days ? <p className="mt-1 text-xs text-danger">{coverage.failed_days} failed</p> : null}
                      {coverage?.missing_days ? <p className="mt-1 text-xs text-warning">{coverage.missing_days} missing</p> : null}
                    </td>
                    <td className="px-3 py-3">
                      <p className="font-mono text-sm font-semibold text-text">{coverage ? formatNumber(coverage.archived_documents) : "—"}<span className="ml-1.5 font-sans text-xs font-normal text-text-subtle">records</span></p>
                      <p className="mt-1 text-xs text-text-muted">{coverage ? `${formatBytes(coverage.archive_bytes)} compressed` : "No archive data"}</p>
                    </td>
                    <td className="px-4 py-3 sm:px-5">
                      <p className="text-sm font-medium text-text">{coverage ? formatDay(coverage.latest_success_day) : "—"}</p>
                      <p className="mt-1 text-xs text-text-muted">{coverage ? `${coverage.lag_days}d lag` : coverageState.detail}</p>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      <BackupIntelligence overview={overview} loading={loading} />
    </motion.section>
  );
}

function BackupPosture({ overview, loading }: { overview: BackupTargetOverview | null; loading: boolean }) {
  const reduceMotion = useReducedMotion();
  const presentation = workerPresentation(overview);
  const worker = overview?.worker;
  const attention = worker?.attention_count ?? 0;

  return (
    <motion.section
      initial={reduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm"
      aria-labelledby="backup-posture-title"
    >
      <h3 id="backup-posture-title" className="sr-only">Backup posture</h3>
      <div className="grid grid-cols-1 divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        <PostureMetric
          label="Pi worker"
          value={worker ? presentation.label : loading ? "Connecting…" : presentation.label}
          detail={worker ? `Heartbeat ${formatAge(worker.heartbeat_age_seconds)}` : presentation.detail}
          tone={worker?.state === "healthy" ? "success" : worker?.state === "offline" ? "danger" : "neutral"}
        />
        <PostureMetric
          label="Attention"
          value={attention === 0 ? "Clear" : formatNumber(attention)}
          detail={attention === 0 ? "No open archive issues" : "Failed, running, or missing days"}
          tone={attention === 0 ? "success" : "warning"}
        />
        <PostureMetric
          label="Active targets"
          value={overview ? `${overview.active_count}/${overview.targets.length}` : "—"}
          detail={overview ? `${overview.planned_count} planned · ${overview.policy.eligible_days} eligible days` : "Checking target activation"}
          tone="primary"
        />
      </div>
    </motion.section>
  );
}

function PostureMetric({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  tone: "success" | "warning" | "info" | "primary" | "danger" | "neutral";
}) {
  const valueClass = tone === "success"
    ? "text-success"
    : tone === "warning"
      ? "text-warning"
      : tone === "danger"
        ? "text-danger"
        : tone === "info"
          ? "text-info"
          : tone === "primary"
            ? "text-primary"
            : "text-text";
  return (
    <div className="min-w-0 bg-surface px-4 py-3.5">
      <p className="text-xs font-medium text-text-subtle">{label}</p>
      <p className={`mt-1 truncate text-base font-semibold ${valueClass}`} title={value}>{value}</p>
      <p className="mt-0.5 truncate text-xs text-text-muted" title={detail}>{detail}</p>
    </div>
  );
}

function CoverageRail({ coverage }: { coverage: BackupTargetCoverage | undefined }) {
  if (!coverage || coverage.expected_days <= 0) {
    return <div role="img" className="mt-2 h-1.5 rounded-full bg-border" aria-label="Coverage unavailable" />;
  }
  const total = coverage.expected_days;
  const width = (value: number) => `${Math.min(100, Math.max(0, (value / total) * 100))}%`;
  return (
    <div
      role="img"
      className="mt-2 flex h-1.5 overflow-hidden rounded-full bg-border"
      aria-label={`Coverage status: ${coverage.archived_days} archived, ${coverage.empty_days} empty, ${coverage.failed_days} failed, ${coverage.running_days} running, ${coverage.missing_days} missing`}
    >
      <span className="bg-success" style={{ width: width(coverage.archived_days) }} title={`${coverage.archived_days} archived`} />
      <span className="bg-text-subtle/50" style={{ width: width(coverage.empty_days) }} title={`${coverage.empty_days} empty`} />
      <span className="bg-danger" style={{ width: width(coverage.failed_days) }} title={`${coverage.failed_days} failed`} />
      <span className="bg-info" style={{ width: width(coverage.running_days) }} title={`${coverage.running_days} running`} />
      <span className="bg-warning" style={{ width: width(coverage.missing_days) }} title={`${coverage.missing_days} missing`} />
    </div>
  );
}

function BackupIntelligence({ overview, loading }: { overview: BackupTargetOverview | null; loading: boolean }) {
  if (loading && !overview) {
    return (
      <div className="grid gap-4 pt-1 lg:grid-cols-2" aria-busy="true" aria-label="Loading backup details">
        {["Needs attention", "Recent activity"].map((label) => (
          <div key={label} className="rounded-2xl border border-border bg-surface p-4">
            <p className="text-sm font-semibold">{label}</p>
            <div className="mt-4 space-y-3">
              {[1, 2, 3].map((item) => <div key={item} className="h-10 animate-pulse rounded-lg bg-surface-subtle" />)}
            </div>
          </div>
        ))}
      </div>
    );
  }
  if (!overview) return null;

  const visibleExceptions = overview.exceptions.slice(0, 6);
  const hiddenExceptionCount = Math.max(0, overview.worker.attention_count - overview.exceptions.length);
  const restoreClassName = overview.restore.status === "verified"
    ? "border-success-border bg-success-subtle text-success"
    : overview.restore.status === "failed"
      ? "border-danger-border bg-danger-subtle text-danger"
      : "border-warning-border bg-warning-subtle text-warning";
  const RestoreIcon = overview.restore.status === "verified" ? ShieldCheck : overview.restore.status === "failed" ? XCircle : ShieldAlert;

  return (
    <div className="space-y-4 pt-1">
      <div className="grid gap-4 xl:grid-cols-2">
        <section className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm" aria-labelledby="backup-exceptions-title">
          <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3 sm:px-5">
            <div className="flex items-center gap-2.5">
              <span className="grid h-9 w-9 place-items-center rounded-lg border border-warning-border bg-warning-subtle text-warning"><FileWarning className="h-4 w-4" aria-hidden="true" /></span>
              <div>
                <h3 id="backup-exceptions-title" className="text-sm font-semibold">Needs attention</h3>
                <p className="mt-0.5 text-xs text-text-muted">Failed or missing archive days</p>
              </div>
            </div>
            <span className={`ui-badge text-xs ${overview.worker.attention_count > 0 ? "border-warning-border bg-warning-subtle text-warning" : "border-success-border bg-success-subtle text-success"}`}>
              {overview.worker.attention_count === 0 ? "Clear" : `${formatNumber(overview.worker.attention_count)} open`}
            </span>
          </div>
          {visibleExceptions.length > 0 ? (
            <div className="divide-y divide-border">
              {visibleExceptions.map((exception) => {
                const presentation = exceptionPresentation(exception.status);
                const StatusIcon = presentation.Icon;
                return (
                  <div key={`${exception.target_id}:${exception.day}`} className="flex items-center gap-3 px-4 py-3 sm:px-5">
                    <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${presentation.className}`}><StatusIcon className={`h-4 w-4 ${exception.status === "running" ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" /></span>
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <p className="truncate text-sm font-medium text-text">{targetLabel(exception.target_id)}</p>
                        <time className="shrink-0 font-mono text-xs text-text-subtle">{exception.day}</time>
                      </div>
                      {exception.status === "failed" && <p className="mt-1 truncate text-xs text-text-muted" title={exception.detail}>{exception.detail}</p>}
                    </div>
                    {exception.action_supported ? (
                      <a href="#hardware-backup-title" className={`ui-badge shrink-0 text-xs ${presentation.className}`}>{presentation.label}</a>
                    ) : (
                      <span className={`ui-badge shrink-0 text-xs ${presentation.className}`}>{presentation.label}</span>
                    )}
                  </div>
                );
              })}
              {(overview.exceptions.length > visibleExceptions.length || hiddenExceptionCount > 0) && (
                <p className="px-4 py-3 text-xs text-text-subtle sm:px-5">Showing the highest-priority days; totals are listed in the source rows.</p>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-2.5 px-4 py-5 text-sm text-success sm:px-5"><CheckCircle2 className="h-5 w-5" aria-hidden="true" />No failed or missing days.</div>
          )}
        </section>

        <section className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm" aria-labelledby="backup-activity-title">
          <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3 sm:px-5">
            <div className="flex items-center gap-2.5">
              <span className="grid h-9 w-9 place-items-center rounded-lg border border-info-border bg-info-subtle text-info"><Activity className="h-4 w-4" aria-hidden="true" /></span>
              <div>
                <h3 id="backup-activity-title" className="text-sm font-semibold">Recent activity</h3>
                <p className="mt-0.5 text-xs text-text-muted">Dashboard requests sent to the Pi worker</p>
              </div>
            </div>
            <span className="text-xs text-text-subtle">{overview.activity.length} records</span>
          </div>
          {overview.activity.length > 0 ? (
            <div className="divide-y divide-border">
              {overview.activity.slice(0, 5).map((request) => {
                const presentation = activityPresentation(request.status);
                const StatusIcon = presentation.Icon;
                return (
                  <div key={request.id} className="flex items-center gap-3 px-4 py-3 sm:px-5">
                    <StatusIcon className={`h-4 w-4 shrink-0 ${request.status === "running" ? "motion-safe:animate-spin text-info" : request.status === "failed" ? "text-danger" : request.status === "success" ? "text-success" : "text-warning"}`} aria-hidden="true" />
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <p className="truncate text-sm font-medium text-text">{targetLabel(request.source)}</p>
                        <span className="shrink-0 text-xs text-text-subtle">{request.action === "run_missing" ? "Run missing" : "Retry failed"}</span>
                      </div>
                      <p className="mt-1 truncate text-xs text-text-muted" title={`${presentation.label} · ${request.requested_by} · ${formatDateTime(request.created_at)}`}>
                        {presentation.label} · {formatDateTime(request.created_at)} · {request.requested_by}
                      </p>
                    </div>
                    <div className="shrink-0 text-right">
                      <p className="font-mono text-sm font-semibold text-text">{request.status === "pending" || request.status === "running" ? `${request.progress.percent}%` : formatDuration(request.duration_seconds)}</p>
                      <p className="mt-0.5 text-xs text-text-subtle">{request.progress.total_days > 0 ? `${request.progress.completed_days}/${request.progress.total_days} days` : "—"}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center gap-2.5 px-4 py-5 text-sm text-text-muted sm:px-5"><CircleDashed className="h-5 w-5" aria-hidden="true" />No dashboard actions recorded yet.</div>
          )}
        </section>
      </div>

      <section className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm" aria-label="Recovery and backup policy">
        <div className="grid md:grid-cols-2 md:divide-x md:divide-border">
          <div className="p-4 sm:p-5" aria-labelledby="backup-restore-title">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <span className={`grid h-9 w-9 place-items-center rounded-lg border ${restoreClassName}`}><RestoreIcon className="h-4 w-4" aria-hidden="true" /></span>
                <div>
                  <h3 id="backup-restore-title" className="text-sm font-semibold">Restore readiness</h3>
                  <p className="mt-0.5 text-xs text-text-muted">Latest recovery evidence</p>
                </div>
              </div>
              <span className={`ui-badge text-xs ${restoreClassName}`}>{overview.restore.status === "not_tested" ? "Not tested" : overview.restore.status}</span>
            </div>
            <p className="mt-3 text-sm leading-5 text-text-muted">{overview.restore.detail}</p>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-xs text-text-subtle">
              <span>{overview.restore.source}</span>
              <span>{overview.restore.last_verified_at ? `Verified ${formatDateTime(overview.restore.last_verified_at)}` : "No verification date"}</span>
            </div>
          </div>

          <div className="border-t border-border p-4 md:border-t-0 sm:p-5" aria-labelledby="backup-policy-title">
            <div className="flex items-center gap-2.5">
              <span className="grid h-9 w-9 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><LockKeyhole className="h-4 w-4" aria-hidden="true" /></span>
              <div>
                <h3 id="backup-policy-title" className="text-sm font-semibold">Policy &amp; safeguards</h3>
                <p className="mt-0.5 text-xs text-text-muted">Retention and archive boundaries</p>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-5 gap-y-3">
              <PolicyValue icon={TimerReset} label="Window" value={`${overview.policy.lookback_days}d lookback`} detail={`${overview.policy.eligible_days} eligible UTC days`} />
              <PolicyValue icon={Clock3} label="Safety hold" value={`${overview.policy.safety_days}d`} detail="Late rollups stay out" />
              <PolicyValue icon={Cloud} label="Archive" value={overview.policy.archive_format} detail={overview.policy.destination_visibility} />
              <PolicyValue icon={ShieldCheck} label="Sensitive" value="Explicit opt-in" detail={overview.policy.sensitive_target_policy.replace("Threat events require ", "")} />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function PolicyValue({ icon: Icon, label, value, detail }: { icon: LucideIcon; label: string; value: string; detail: string }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs font-medium text-text-subtle"><Icon className="h-3.5 w-3.5 text-primary" aria-hidden="true" />{label}</div>
      <p className="mt-1 truncate font-mono text-sm font-semibold text-text" title={value}>{value}</p>
      <p className="mt-0.5 truncate text-xs text-text-muted" title={detail}>{detail}</p>
    </div>
  );
}

function LegendDot({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span className={`h-2 w-2 rounded-full ${className}`} aria-hidden="true" />
      {label}
    </span>
  );
}
