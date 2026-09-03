"use client";
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";
import { AttackerTable } from "@/components/dashboard/AttackerTable";
import { HardwareMonitor } from "@/components/dashboard/HardwareMonitor";

export default function SystemHealthPage() {
  return (
    <div className="space-y-6 animate-in fade-in duration-500">
       
       {/* ---------------- Hardware Task Manager ---------------- */}
       <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 flex flex-col hover:border-purple-900/50 transition-colors shadow-[0_0_20px_rgba(168,85,247,0.05)] h-[350px]">
          <h3 className="text-sm font-semibold text-white tracking-tight mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Hardware Telemetry (Real-time)
          </h3>
          <div className="flex-1">
             <HardwareMonitor />
          </div>
       </div>

       {/* ---------------- Live Events & Top Attackers ---------------- */}
       <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 h-[450px]">
          {/* Live Event Stream */}
          <div className="h-full shadow-[0_0_20px_rgba(168,85,247,0.05)]">
            <LiveEventStream />
          </div>
          {/* Top Attackers */}
          <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 flex flex-col hover:border-purple-900/50 transition-colors h-full overflow-hidden shadow-[0_0_20px_rgba(168,85,247,0.05)]">
            <h3 className="text-sm font-semibold text-white tracking-tight mb-4 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
              Top Threat Actors
            </h3>
            <AttackerTable />
          </div>
       </div>
    </div>
  );
}