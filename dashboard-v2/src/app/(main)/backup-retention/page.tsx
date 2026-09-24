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
  ShieldCheck,
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
    <div className="space-y-6 pb-10">
      <motion.header
        initial={reduceMotion ? false : { opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
        className="relative overflow-hidden rounded-[1.25rem] border border-primary-border bg-gradient-to-br from-primary-subtle via-surface to-surface p-5 shadow-[0_14px_42px_color-mix(in_srgb,var(--primary)_10%,transparent)] sm:p-7"
      >
        <div className="pointer-events-none absolute -right-16 -top-24 h-64 w-64 rounded-full bg-primary/10 blur-3xl" aria-hidden="true" />
        <div className="pointer-events-none absolute right-24 top-8 h-2 w-2 rounded-full bg-primary shadow-[0_0_20px_var(--primary)]" aria-hidden="true" />
        <div className="pointer-events-none absolute right-40 top-20 h-1.5 w-1.5 rounded-full bg-info shadow-[0_0_16px_var(--info)]" aria-hidden="true" />

        <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="flex min-w-0 items-start gap-4">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-primary-border bg-surface text-primary shadow-sm">
              <ShieldCheck className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-primary">Data protection / operations</p>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">Backup control room</h1>
              <p className="mt-2 max-w-2xl text-sm text-text-muted">See archive coverage, trigger Pi actions, and verify the cloud destination from one focused view.</p>
              <div className="mt-4 flex flex-wrap items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-text-subtle">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-success-border bg-success-subtle px-2.5 py-1 text-success"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-success" aria-hidden="true" />Pi connected</span>
                <span className="rounded-full border border-border bg-surface/70 px-2.5 py-1">Private archive</span>
                <span className="rounded-full border border-border bg-surface/70 px-2.5 py-1">30-day lookback</span>
              </div>
            </div>
          </div>
          <Link href="/system-health" className="ui-button min-h-10 shrink-0 gap-2 self-start text-xs lg:self-auto">
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            System health
            <ArrowUpRight className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
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
