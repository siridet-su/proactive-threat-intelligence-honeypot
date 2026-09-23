"use client";

import Link from "next/link";
import { Archive, ArrowLeft, CalendarClock, Database, FolderArchive, LockKeyhole, ShieldCheck } from "lucide-react";

import { HardwareBackupStatus } from "@/components/dashboard/HardwareBackupStatus";

const sourceCards = [
  {
    title: "Hardware rollups",
    description: "Minute-level hardware history used by the System Health charts.",
    collection: "hardware_metrics_1m",
    cadence: "Daily archive",
    state: "Active",
    stateClassName: "border-success-border bg-success-subtle text-success",
    icon: Archive,
  },
  {
    title: "Threat event history",
    description: "A future source for retained event evidence and investigation timelines.",
    collection: "event archive",
    cadence: "Source not registered",
    state: "Planned",
    stateClassName: "border-border bg-surface-subtle text-text-subtle",
    icon: FolderArchive,
  },
  {
    title: "Filesystem audit history",
    description: "A future source for long-term filesystem activity and audit sessions.",
    collection: "filesystem archive",
    cadence: "Source not registered",
    state: "Planned",
    stateClassName: "border-border bg-surface-subtle text-text-subtle",
    icon: Database,
  },
] as const;

export default function BackupRetentionPage() {
  return (
    <div className="space-y-6 pb-8">
      <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 lg:flex-row lg:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Operations / Data protection</p>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">Backup &amp; retention</h1>
          <p className="mt-2 max-w-3xl text-sm text-text-muted">Central visibility for protected data sources, archive coverage, and retention policy. Each source can add its own worker without crowding System Health.</p>
        </div>
        <Link href="/system-health" className="ui-button min-h-10 shrink-0 gap-2 text-xs">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back to system health
        </Link>
      </header>

      <section aria-labelledby="backup-sources-title">
        <div className="mb-3 flex items-end justify-between gap-3">
          <div>
            <h2 id="backup-sources-title" className="text-base font-semibold">Backup sources</h2>
            <p className="mt-1 text-xs text-text-muted">Source-level status is designed to grow as more retained datasets are registered.</p>
          </div>
          <span className="ui-badge border-info-border bg-info-subtle text-info">{sourceCards.filter((source) => source.state === "Active").length} active source</span>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {sourceCards.map(({ title, description, collection, cadence, state, stateClassName, icon: Icon }) => (
            <article key={title} className="ui-panel flex min-h-[176px] flex-col justify-between p-5 transition-colors duration-200 hover:border-border-strong">
              <div>
                <div className="flex items-start justify-between gap-3">
                  <span className="rounded-lg bg-primary-subtle p-2.5 text-primary"><Icon className="h-5 w-5" aria-hidden="true" /></span>
                  <span className={`ui-badge ${stateClassName}`}>{state}</span>
                </div>
                <h3 className="mt-4 text-sm font-semibold">{title}</h3>
                <p className="mt-1 text-xs leading-5 text-text-muted">{description}</p>
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-[11px] text-text-subtle">
                <span className="font-mono">{collection}</span>
                <span>{cadence}</span>
              </div>
            </article>
          ))}
        </div>
      </section>

      <HardwareBackupStatus />

      <section className="ui-panel overflow-hidden" aria-labelledby="backup-policy-title">
        <div className="border-b border-border px-5 py-4 sm:px-6">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 id="backup-policy-title" className="text-base font-semibold">Automation &amp; policy</h2>
          </div>
          <p className="mt-1 text-xs text-text-muted">Current worker behavior is visible here before manual control actions are introduced.</p>
        </div>
        <div className="grid gap-px bg-border sm:grid-cols-3">
          <PolicyItem icon={CalendarClock} label="Schedule" value="Daily · 03:30 local time" detail="Persistent systemd timer on the Pi" />
          <PolicyItem icon={LockKeyhole} label="Safety window" value="2 completed days" detail="Avoids archiving late-arriving rollups" />
          <PolicyItem icon={Archive} label="Archive policy" value="30-day lookback" detail="Compressed JSONL uploaded to private B2" />
        </div>
        <div className="border-t border-border bg-surface-subtle/50 px-5 py-4 text-xs text-text-muted sm:px-6">
          Manual run, retry, and restore actions will be connected through the Pi control plane. The browser will create an audited request; it will not execute SSH or shell commands directly.
        </div>
      </section>
    </div>
  );
}

function PolicyItem({ icon: Icon, label, value, detail }: { icon: typeof Archive; label: string; value: string; detail: string }) {
  return (
    <div className="bg-surface p-5">
      <div className="flex items-center gap-2 text-xs font-medium text-text-muted">
        <Icon className="h-4 w-4 text-primary" aria-hidden="true" />
        {label}
      </div>
      <p className="mt-3 font-mono text-sm text-text">{value}</p>
      <p className="mt-1 text-xs leading-5 text-text-subtle">{detail}</p>
    </div>
  );
}
