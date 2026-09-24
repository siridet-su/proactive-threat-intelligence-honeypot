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

import { isBackupTargetOverview, type BackupTargetId, type BackupTargetOverview } from "@/lib/dashboardTypes";

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
