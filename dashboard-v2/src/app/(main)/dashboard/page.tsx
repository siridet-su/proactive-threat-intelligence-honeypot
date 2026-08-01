"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import RegionalMap from "@/components/dashboard/RegionalMap";
import AttackRateChart from "@/components/dashboard/AttackRateChart";
import { incidentLogs } from "@/lib/mockData"; 
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";
import { AttackerTable } from "@/components/dashboard/AttackerTable";
import { mockLiveEvents, mockAttackers } from "@/data/honeypotMockData";
import { HardwareMonitor } from "@/components/dashboard/HardwareMonitor";
// ข้อมูลสำหรับกราฟโดนัท (Status Split)
const statusData = [
  { name: "Completed", value: 45, color: "#a855f7" }, // สีม่วง
  { name: "Running", value: 30, color: "#34d399" },   // สีเขียว
  { name: "Failed", value: 15, color: "#f87171" },    // สีแดง
  { name: "Queued", value: 10, color: "#52525b" },    // สีเทา
];

export default function DashboardPage() {
  return (
    <div className="space-y-6 animate-in fade-in duration-500">
       
       {/* ---------------- Global Activity Matrix (แผนที่กว้างเต็มจอ) ---------------- */}
       <div className="bg-[#111116] border border-slate-800/80 rounded-xl hover:border-purple-900/50 transition-colors flex flex-col overflow-hidden">
          <div className="px-6 py-5 border-b border-slate-800/80 flex justify-between items-center bg-[#111116] z-10">
             <div>
                <h2 className="text-sm font-semibold text-white tracking-tight">Global Activity Matrix</h2>
                <p className="text-[11px] text-slate-500 mt-0.5">Distributed sensor telemetry · 1,248 sessions</p>
             </div>
             <div className="flex items-center gap-4 text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-500"></span>Completed</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400"></span>Running</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400"></span>Failed</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-500"></span>Queued</span>
             </div>
          </div>
          {/* แผนที่ซูมได้ */}
          <div className="h-[400px] w-full bg-[#09090b]">
             <RegionalMap />
          </div>
       </div>

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

// ---------------- Sub-component สำหรับ Tactic Frequency ----------------
function TacticBar({ label, count, max, color }: any) {
  const percentage = (count / max) * 100;
  return (
    <div className="flex items-center gap-3">
      <div className="w-28 text-right text-[10px] font-mono text-slate-400 truncate">{label}</div>
      <div className="flex-1 h-2 bg-[#18181b] rounded-full overflow-hidden flex">
         <div className={`h-full ${color} rounded-full`} style={{ width: `${percentage}%` }}></div>
      </div>
      <div className="w-6 text-left text-[10px] font-mono text-slate-300">{count}</div>
    </div>
  );
}