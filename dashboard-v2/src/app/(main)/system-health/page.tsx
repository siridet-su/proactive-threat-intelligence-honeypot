"use client";

import Link from "next/link";
import { Activity, Archive, ArrowUpRight, History, Radio, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

import { AttackerTable } from "@/components/dashboard/AttackerTable";
import { HardwareMonitor } from "@/components/dashboard/HardwareMonitor";
import { HardwareHistory } from "@/components/dashboard/HardwareHistory";

export default function SystemHealthPage() {
  return (
    <div className="space-y-5 pb-8">
      <motion.header
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
        className="flex flex-col gap-4 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between"
      >
        <div>
          <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">
            <Activity className="h-3.5 w-3.5" aria-hidden="true" />
            Operations / Platform
          </div>
          <h1 className="mt-2 text-2xl font-semibold leading-8 tracking-tight text-text sm:text-[28px]">System health</h1>
          <p className="mt-1.5 max-w-2xl text-sm text-text-muted">Live hardware state, source activity, and retained performance signals in one view.</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="ui-badge border-success-border bg-success-subtle text-success">
            <span className="relative flex h-2 w-2" aria-hidden="true">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-50 motion-reduce:hidden" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
            </span>
            <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            Monitoring
          </span>
          <Link href="/backup-retention" className="ui-button min-h-9 shrink-0 gap-2 px-3 text-xs">
            <Archive className="h-4 w-4 text-primary" aria-hidden="true" />
            Backup &amp; retention
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>
      </motion.header>

      <HardwareMonitor />
      <AttackerTable />

      <HardwareHistory />

      <div className="flex items-center gap-2 px-1 text-[11px] text-text-subtle">
        <ShieldCheck className="h-3.5 w-3.5 text-success" aria-hidden="true" />
        <span>Live values come from hardware_live; history is read from minute rollups in hardware_metrics_1m.</span>
        <History className="ml-auto hidden h-3.5 w-3.5 sm:block" aria-hidden="true" />
      </div>
    </div>
  );
}
