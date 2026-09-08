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
          <span className="ui-badge border-info-border bg-info-subtle text-info">Telemetry refresh · 10s</span>
       </header>

       {/* ---------------- Hardware Task Manager ---------------- */}
       <section className="ui-panel flex min-h-[430px] flex-col p-5 sm:p-6 lg:h-[450px]">
          <div className="mb-4 flex items-center gap-2"><span aria-hidden="true" className="h-2 w-2 rounded-full bg-success"></span>
            <h2 className="text-base font-semibold">Hardware telemetry</h2><span className="text-xs text-text-muted">Real-time</span>
          </div>
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
            <h2 className="mb-4 text-base font-semibold">Top threat actors</h2>
            <AttackerTable />
          </div>
       </div>
    </div>
  );
}
