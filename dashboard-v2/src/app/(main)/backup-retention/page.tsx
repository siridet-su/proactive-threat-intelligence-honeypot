"use client";

import Link from "next/link";
import { motion, useReducedMotion } from "framer-motion";
import {
  Archive,
  ArrowLeft,
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
          <p className="mt-1.5 max-w-2xl text-sm text-text-muted">Review archive coverage, run Pi backup actions, and check recovery readiness.</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link href="/system-health" className="ui-button min-h-9 shrink-0 gap-2 px-3 text-xs">
            <ArrowLeft className="h-4 w-4" aria-hidden="true" />
            System health
          </Link>
        </div>
      </motion.header>

      <HardwareBackupStatus />

      <BackupSourceMap />
    </div>
  );
}
