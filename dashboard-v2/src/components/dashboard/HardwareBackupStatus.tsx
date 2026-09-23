"use client";

import { useEffect, useMemo, useState } from "react";
import { Archive, AlertTriangle, CalendarDays, CheckCircle2, Clock3, Database, RefreshCw } from "lucide-react";

import { RegionState } from "@/components/ui/RegionState";
import {
  isHardwareBackupStatus,
  type HardwareBackupDay,
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
  return Number.isFinite(date.getTime()) ? date.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }) : "—";
}

function formatDateTime(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
}

function dayLabel(day: HardwareBackupDay) {
  if (day.status === "missing") return `${day.day}: no manifest recorded`;
  if (day.status === "running") return `${day.day}: backup in progress`;
  if (day.status === "failed") return `${day.day}: backup failed${day.error ? ` — ${day.error}` : ""}`;
  if (day.document_count === 0) return `${day.day}: completed, no rollup documents`;
  return `${day.day}: completed, ${formatNumber(day.document_count)} documents, ${formatBytes(day.archive_bytes)}`;
}

function visualDayStatus(day: HardwareBackupDay) {
  if (day.status === "success" && day.document_count === 0) return "empty";
  return day.status;
}

function statePresentation(data: HardwareBackupStatusData) {
  const { summary } = data;
  if (summary.failed_days > 0) {
    return { state: "attention" as BackupState, label: "Needs attention", description: `${summary.failed_days} backup day${summary.failed_days === 1 ? "" : "s"} failed`, className: "border-danger-border bg-danger-subtle text-danger", Icon: AlertTriangle };
  }
  if (summary.running_days > 0) {
    return { state: "running" as BackupState, label: "Backup in progress", description: "The scheduled worker is writing a manifest", className: "border-info-border bg-info-subtle text-info", Icon: Clock3 };
  }
  if (summary.missing_days > 0) {
    return { state: "partial" as BackupState, label: "Partial coverage", description: `${summary.missing_days} expected day${summary.missing_days === 1 ? " is" : "s are"} not recorded`, className: "border-warning-border bg-warning-subtle text-warning", Icon: AlertTriangle };
  }
  if (summary.successful_days > 0) {
    return { state: "healthy" as BackupState, label: "Healthy", description: "All expected backup days have a manifest", className: "border-success-border bg-success-subtle text-success", Icon: CheckCircle2 };
  }
  return { state: "not_started" as BackupState, label: "Not started", description: "Waiting for the first scheduled backup", className: "border-border bg-surface-subtle text-text-muted", Icon: Archive };
}

export function HardwareBackupStatus() {
  const [data, setData] = useState<HardwareBackupStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

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

  const refresh = () => {
    setRefreshing(true);
    setReloadToken((current) => current + 1);
  };

  const presentation = useMemo(() => (data ? statePresentation(data) : null), [data]);
  const coveragePercent = data && data.summary.expected_days > 0
    ? Math.min(100, Math.round((data.summary.successful_days / data.summary.expected_days) * 100))
    : 0;

  return (
    <section className="ui-panel flex flex-col overflow-hidden p-5 sm:p-6" aria-labelledby="hardware-backup-title">
      <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Archive className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 id="hardware-backup-title" className="text-base font-semibold">Hardware backup</h2>
          </div>
          <p className="mt-1 text-xs text-text-muted">Daily compressed archives of hardware_metrics_1m stored in Backblaze B2.</p>
        </div>
        <div className="flex items-center gap-2">
          {presentation && (
            <span className={`ui-badge ${presentation.className}`} aria-live="polite">
              <presentation.Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {presentation.label}
            </span>
          )}
          <button type="button" onClick={refresh} disabled={loading || refreshing} className="ui-button min-h-9 px-3 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {loading && !data ? (
        <div className="grid gap-4 pt-4" aria-busy="true" aria-label="Loading hardware backup status">
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            {Array.from({ length: 4 }, (_, index) => <div key={index} className="ui-skeleton h-20 rounded-lg" />)}
          </div>
          <div className="ui-skeleton h-14 rounded-lg" />
        </div>
      ) : error && !data ? (
        <div className="pt-4">
          <RegionState kind="error" title="Hardware backup status unavailable" description={`${error}. Retry when the dashboard can reach MongoDB.`} />
        </div>
      ) : data && presentation ? (
        <div className="flex flex-col gap-4 pt-4">
          {error && <p role="status" className="text-xs text-warning">{error} · showing the last successful result</p>}

          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <BackupStat icon={CalendarDays} label="Coverage" value={`${data.summary.successful_days}/${data.summary.expected_days}`} detail={`${coveragePercent}% of expected days`} />
            <BackupStat icon={CheckCircle2} label="Latest archive" value={formatDay(data.summary.latest_success_day)} detail={presentation.description} />
            <BackupStat icon={Database} label="Archived records" value={formatNumber(data.summary.archived_documents)} detail={`${formatBytes(data.summary.archive_bytes)} compressed`} />
            <BackupStat icon={Clock3} label="Last completed" value={formatDateTime(data.summary.last_completed_at)} detail={`Window ends ${formatDay(data.expected_window.to.slice(0, 10))}`} />
          </div>

          <div className="rounded-lg border border-border bg-surface-subtle p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h3 className="text-xs font-medium text-text-muted">Backup coverage by UTC day</h3>
                <p className="mt-1 text-xs text-text-subtle">{formatDay(data.expected_window.from.slice(0, 10))} → {formatDay(data.expected_window.to.slice(0, 10))} · current and previous day are held for late rollups</p>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-[11px] text-text-subtle" aria-label="Backup status legend">
                <LegendDot className="bg-success" label="Archived" />
                <LegendDot className="bg-text-subtle" label="Empty" />
                <LegendDot className="bg-warning" label="Missing" />
                <LegendDot className="bg-danger" label="Failed" />
              </div>
            </div>
            <div className="mt-4 grid grid-cols-7 gap-1.5 sm:grid-cols-10 md:grid-cols-12 lg:grid-cols-[repeat(15,minmax(0,1fr))]" role="list" aria-label="Hardware backup days">
              {data.days.map((day) => {
                const status = visualDayStatus(day);
                return (
                  <div
                    key={day.day}
                    role="listitem"
                    aria-label={dayLabel(day)}
                    title={dayLabel(day)}
                    className={`flex min-h-11 items-center justify-center rounded-md border text-xs font-mono transition-colors duration-200 ${
                      status === "success" ? "border-success-border bg-success-subtle text-success" :
                      status === "empty" ? "border-border bg-surface text-text-subtle" :
                      status === "running" ? "border-info-border bg-info-subtle text-info" :
                      status === "failed" ? "border-danger-border bg-danger-subtle text-danger" :
                      "border-warning-border bg-warning-subtle text-warning"
                    }`}
                  >
                    {day.day.slice(8, 10)}
                  </div>
                );
              })}
            </div>
            <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-surface-hover" aria-label={`Backup coverage ${coveragePercent}%`}>
              <div className="h-full rounded-full bg-success transition-[width] duration-500 ease-out" style={{ width: `${coveragePercent}%` }} />
            </div>
          </div>

          <p className="flex items-center gap-1.5 text-xs text-text-subtle">
            <Clock3 className="h-3.5 w-3.5" aria-hidden="true" />
            Automatic worker · last started {formatDateTime(data.summary.last_started_at)} · collection <span className="font-mono">{data.collection}</span>
          </p>
        </div>
      ) : (
        <div className="pt-4"><RegionState kind="empty" title="No hardware backup status" description="The backup worker has not written a manifest yet." /></div>
      )}
    </section>
  );
}

function BackupStat({ icon: Icon, label, value, detail }: { icon: typeof Archive; label: string; value: string; detail: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-border bg-surface-subtle p-3 transition-colors duration-200 hover:border-border-strong hover:bg-surface-hover">
      <div className="flex items-center gap-2">
        <span className="rounded-md bg-primary-subtle p-2 text-primary"><Icon className="h-4 w-4" aria-hidden="true" /></span>
        <span className="min-w-0">
          <span className="block text-xs font-medium text-text-muted">{label}</span>
          <span className="block truncate font-mono text-base text-text" title={value}>{value}</span>
        </span>
      </div>
      <p className="mt-2 truncate text-[11px] text-text-subtle" title={detail}>{detail}</p>
    </div>
  );
}

function LegendDot({ className, label }: { className: string; label: string }) {
  return <span className="inline-flex items-center gap-1"><span className={`h-2 w-2 rounded-full ${className}`} aria-hidden="true" />{label}</span>;
}
