"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  Archive,
  ArrowUpRight,
  CheckCircle2,
  Database,
  FolderArchive,
  LoaderCircle,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import {
  isBackupTargetOverview,
  type BackupTargetId,
  type BackupTargetOverview,
  type BackupTargetStatus,
} from "@/lib/dashboardTypes";

const SOURCE_CARDS: Array<{
  targetId: BackupTargetId;
  title: string;
  description: string;
  collection: string;
  icon: LucideIcon;
}> = [
  {
    targetId: "hardware_metrics_1m",
    title: "Hardware rollups",
    description: "Minute-level history for System Health.",
    collection: "hardware_metrics_1m",
    icon: Archive,
  },
  {
    targetId: "threat_events",
    title: "Threat event history",
    description: "Canonical investigation evidence with a scoped sensitive-data policy.",
    collection: "events",
    icon: FolderArchive,
  },
  {
    targetId: "filesystem_audit",
    title: "Filesystem audit history",
    description: "Authoritative CWD events and session state; derived projections are rebuilt.",
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

function relativeWorkerState(overview: BackupTargetOverview | null, targetId: BackupTargetId) {
  const target = overview?.targets.find((item) => item.target_id === targetId);
  if (!target || target.state !== "active") return "Awaiting Pi activation";
  if (!target.last_seen_at) return "Enabled target";
  const seen = new Date(target.last_seen_at);
  if (!Number.isFinite(seen.getTime())) return "Enabled target";
  return `Worker seen ${seen.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`;
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
      aria-labelledby="backup-sources-title"
    >
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-primary">Protection map</p>
          <h2 id="backup-sources-title" className="mt-1 text-lg font-semibold tracking-tight">Data sources</h2>
        </div>
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-info-border bg-info-subtle px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-info" aria-live="polite">
          {error ? <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" /> : <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />}
          {error ? "Status unavailable" : `${activeCount} active · ${plannedCount} planned`}
        </span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        {SOURCE_CARDS.map(({ targetId, title, description, collection, icon: Icon }, index) => {
          const presentation = statePresentation(overview, targetId, loading);
          const target = overview?.targets.find((item) => item.target_id === targetId);
          const coverage = target?.coverage;
          const coverageState = coveragePresentation(target);
          const checkedPercent = coverage && coverage.expected_days > 0
            ? Math.round((coverage.successful_days / coverage.expected_days) * 100)
            : 0;
          return (
            <motion.article
              key={targetId}
              initial={reduceMotion ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: reduceMotion ? 0 : 0.12 + index * 0.06, ease: [0.22, 1, 0.36, 1] }}
              whileHover={reduceMotion ? undefined : { y: -3 }}
              className="group rounded-xl border border-border bg-surface p-4 shadow-sm transition-colors duration-200 hover:border-border-strong hover:shadow-md"
            >
              <div className="flex items-start justify-between gap-3">
                <span className="grid h-9 w-9 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><Icon className="h-4 w-4" aria-hidden="true" /></span>
                <span className={`ui-badge text-[10px] ${presentation.className}`}>
                  {loading && !overview && <LoaderCircle className="h-3 w-3 animate-spin" aria-hidden="true" />}
                  {presentation.label}
                </span>
              </div>
              <h3 className="mt-4 text-sm font-semibold">{title}</h3>
              <p className="mt-1 min-h-10 text-xs leading-5 text-text-muted">{description}</p>
              <div className="mt-4 rounded-lg border border-border bg-surface-subtle/70 p-3">
                <div className="flex items-center justify-between gap-2 text-[10px]">
                  <span className="font-semibold uppercase tracking-[0.12em] text-text-subtle">Archive coverage</span>
                  <span className={`font-semibold ${coverageState.className}`}>{coverageState.label}</span>
                </div>
                <div
                  className="mt-2 h-1.5 overflow-hidden rounded-full bg-border"
                  role="progressbar"
                  aria-label={`${title} checked backup window`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={checkedPercent}
                >
                  <motion.span
                    className="block h-full rounded-full bg-success transition-[width] duration-500"
                    initial={reduceMotion ? false : { width: 0 }}
                    animate={{ width: `${checkedPercent}%` }}
                    transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
                  />
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2 text-[10px]">
                  <div>
                    <p className="text-text-subtle">Window checked</p>
                    <p className="mt-0.5 font-mono font-semibold text-text">
                      {coverage ? `${coverage.successful_days}/${coverage.expected_days}` : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-text-subtle">Documents</p>
                    <p className="mt-0.5 font-mono font-semibold text-text">
                      {coverage ? formatNumber(coverage.archived_documents) : "—"}
                    </p>
                  </div>
                </div>
                <div className="mt-2 flex items-center justify-between gap-2 border-t border-border pt-2 text-[10px] text-text-subtle">
                  <span>{coverage ? formatBytes(coverage.archive_bytes) : "—"} compressed</span>
                  <span>Last {coverage ? formatDay(coverage.latest_success_day) : "—"}</span>
                </div>
                <p className="mt-2 text-[10px] leading-4 text-text-subtle">{coverageState.detail}</p>
              </div>
              <div className="mt-4 flex items-center justify-between gap-2 border-t border-border pt-3 text-[10px] text-text-subtle">
                <div className="min-w-0">
                  <p className="truncate font-mono" title={collection}>{collection}</p>
                  <p className="mt-1 truncate text-[10px] text-text-subtle/80">{relativeWorkerState(overview, targetId)}</p>
                </div>
                <ArrowUpRight className="h-3.5 w-3.5 shrink-0 opacity-0 transition-opacity duration-200 group-hover:opacity-100" aria-hidden="true" />
              </div>
            </motion.article>
          );
        })}
      </div>
    </motion.section>
  );
}
