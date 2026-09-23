"use client";
import Link from "next/link";
import { Archive, ArrowUpRight } from "lucide-react";
import { AttackerTable } from "@/components/dashboard/AttackerTable";
import { HardwareMonitor } from "@/components/dashboard/HardwareMonitor";

export default function SystemHealthPage() {
  return (
    <div className="space-y-6 pb-8">
       <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-end">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Operations / Platform</p>
            <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">System health</h1>
            <p className="mt-2 text-sm text-text-muted">Review realtime and historical hardware telemetry supporting the honeypot.</p>
          </div>
          <Link href="/backup-retention" className="ui-button min-h-10 shrink-0 gap-2 text-xs">
            <Archive className="h-4 w-4 text-primary" aria-hidden="true" />
            Backup &amp; retention
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
       </header>

       {/* ---------------- Hardware Task Manager ---------------- */}
       <section className="ui-panel flex min-h-[500px] flex-col p-5 sm:p-6">
          <div className="flex-1">
            <HardwareMonitor />
          </div>
       </section>

       {/* ---------------- Top Source Summary ---------------- */}
       <div className="grid grid-cols-1 gap-6">
          <div className="ui-panel flex min-h-[420px] flex-col overflow-hidden p-5 sm:p-6">
            <div className="mb-4"><h2 className="text-base font-semibold">Top source IPs</h2><p className="mt-1 text-xs text-text-muted">Ranked by observed events in the current live feed.</p></div>
            <AttackerTable />
          </div>
       </div>
    </div>
  );
}
