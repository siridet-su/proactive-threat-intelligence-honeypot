"use client";
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";
import { AttackerTable } from "@/components/dashboard/AttackerTable";
import { HardwareMonitor } from "@/components/dashboard/HardwareMonitor";

export default function SystemHealthPage() {
  return (
    <div className="space-y-6 pb-8">
       <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-end">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Operations / Platform</p>
            <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">System health</h1>
            <p className="mt-2 text-sm text-text-muted">Review the telemetry and live event surface supporting the honeypot.</p>
          </div>
       </header>

       {/* ---------------- Hardware Task Manager ---------------- */}
       <section className="ui-panel flex min-h-[500px] flex-col p-5 sm:p-6 lg:h-[510px]">
          <div className="flex-1">
            <HardwareMonitor />
          </div>
       </section>

       {/* ---------------- Live Events & Top Attackers ---------------- */}
       <div className="grid grid-cols-1 gap-6 xl:grid-cols-2 xl:min-h-[460px]">
          {/* Live Event Stream */}
          <div className="min-h-[420px] xl:h-full">
            <LiveEventStream />
          </div>
          {/* Top Attackers */}
          <div className="ui-panel flex min-h-[420px] flex-col overflow-hidden p-5 sm:p-6 xl:h-full">
            <div className="mb-4"><h2 className="text-base font-semibold">Top source IPs</h2><p className="mt-1 text-xs text-text-muted">Ranked by observed events in the current live feed.</p></div>
            <AttackerTable />
          </div>
       </div>
    </div>
  );
}
