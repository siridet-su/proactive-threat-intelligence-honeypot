"use client";

import Link from "next/link";
import { motion, useReducedMotion } from "framer-motion";
import {
  Archive,
  ArrowLeft,
  ArrowUpRight,
  CalendarClock,
  CheckCircle2,
  Database,
  FolderArchive,
  LockKeyhole,
  Radio,
  TimerReset,
} from "lucide-react";

import { HardwareBackupStatus } from "@/components/dashboard/HardwareBackupStatus";

const sourceCards = [
  {
    title: "Hardware rollups",
    description: "Minute-level history for System Health.",
    collection: "hardware_metrics_1m",
    state: "Active",
    stateClassName: "border-success-border bg-success-subtle text-success",
    icon: Archive,
  },
  {
    title: "Threat event history",
    description: "Reserved for long-term investigation evidence.",
    collection: "event archive",
    state: "Planned",
    stateClassName: "border-border bg-surface-subtle text-text-subtle",
    icon: FolderArchive,
  },
  {
    title: "Filesystem audit history",
    description: "Reserved for durable activity sessions.",
    collection: "filesystem archive",
    state: "Planned",
    stateClassName: "border-border bg-surface-subtle text-text-subtle",
    icon: Database,
  },
] as const;

export default function BackupRetentionPage() {
  const reduceMotion = useReducedMotion();

  return (
    <div className="space-y-5 pb-8">
      <motion.header
        initial={reduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
        className="flex flex-col gap-4 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between"
        aria-labelledby="backup-page-title"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">
            <Archive className="h-3.5 w-3.5" aria-hidden="true" />
            Data protection / operations
          </div>
          <h1 id="backup-page-title" className="mt-2 text-2xl font-semibold leading-8 tracking-tight text-text sm:text-[28px]">Backup &amp; retention</h1>
          <p className="mt-1.5 max-w-2xl text-sm text-text-muted">Protect retained history, trigger Pi backup actions, and verify the private cloud archive in one view.</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="ui-badge border-success-border bg-success-subtle text-success">
            <span className="relative flex h-2 w-2" aria-hidden="true">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-50 motion-reduce:hidden" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
            </span>
            <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            Pi connected
          </span>
          <Link href="/system-health" className="ui-button min-h-9 shrink-0 gap-2 px-3 text-xs">
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            System health
          </Link>
        </div>
      </motion.header>

      <HardwareBackupStatus />

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
          <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-info-border bg-info-subtle px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-info"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />1 active · 2 planned</span>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {sourceCards.map(({ title, description, collection, state, stateClassName, icon: Icon }, index) => (
            <motion.article
              key={title}
              initial={reduceMotion ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: reduceMotion ? 0 : 0.12 + index * 0.06, ease: [0.22, 1, 0.36, 1] }}
              whileHover={reduceMotion ? undefined : { y: -3 }}
              className="group rounded-xl border border-border bg-surface p-4 shadow-sm transition-colors duration-200 hover:border-border-strong hover:shadow-md"
            >
              <div className="flex items-start justify-between gap-3">
                <span className="grid h-9 w-9 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><Icon className="h-4 w-4" aria-hidden="true" /></span>
                <span className={`ui-badge text-[10px] ${stateClassName}`}>{state}</span>
              </div>
              <h3 className="mt-4 text-sm font-semibold">{title}</h3>
              <p className="mt-1 text-xs text-text-muted">{description}</p>
              <div className="mt-4 flex items-center justify-between gap-2 border-t border-border pt-3 text-[10px] text-text-subtle">
                <span className="truncate font-mono" title={collection}>{collection}</span>
                <ArrowUpRight className="h-3.5 w-3.5 shrink-0 opacity-0 transition-opacity duration-200 group-hover:opacity-100" aria-hidden="true" />
              </div>
            </motion.article>
          ))}
        </div>
      </motion.section>

      <motion.section
        initial={reduceMotion ? false : { opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: reduceMotion ? 0 : 0.16, ease: [0.22, 1, 0.36, 1] }}
        className="grid gap-3 sm:grid-cols-3"
        aria-label="Backup policy"
      >
        <PolicyPill icon={CalendarClock} label="Schedule" value="Daily · 03:30" detail="Pi systemd timer" />
        <PolicyPill icon={LockKeyhole} label="Safety hold" value="2 completed days" detail="Late rollups window" />
        <PolicyPill icon={TimerReset} label="Archive window" value="30-day lookback" detail="Compressed JSONL · private B2" />
      </motion.section>
    </div>
  );
}

function PolicyPill({ icon: Icon, label, value, detail }: { icon: typeof Archive; label: string; value: string; detail: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-surface px-4 py-3 shadow-sm transition-colors duration-200 hover:border-border-strong hover:bg-surface-hover">
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><Icon className="h-4 w-4" aria-hidden="true" /></span>
      <div className="min-w-0">
        <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-text-subtle">{label}</p>
        <p className="mt-0.5 truncate font-mono text-xs font-medium text-text">{value}</p>
        <p className="mt-0.5 truncate text-[10px] text-text-muted">{detail}</p>
      </div>
    </div>
  );
}
