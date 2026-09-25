"use client";

import Link from "next/link";
import { motion, useReducedMotion } from "framer-motion";
import {
  Archive,
  ArrowLeft,
  CalendarClock,
  LockKeyhole,
  Radio,
  TimerReset,
} from "lucide-react";

import { BackupSourceMap } from "@/components/dashboard/BackupSourceMap";
import { HardwareBackupStatus } from "@/components/dashboard/HardwareBackupStatus";

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
          <p className="mt-1.5 max-w-2xl text-sm text-text-muted">Track archive coverage by source, then manage Pi hardware backup operations.</p>
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

      <BackupSourceMap />

      <HardwareBackupStatus />

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
