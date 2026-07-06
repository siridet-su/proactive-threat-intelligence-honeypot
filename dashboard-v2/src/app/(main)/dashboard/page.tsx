"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import RegionalMap from "@/components/dashboard/RegionalMap";
import AttackRateChart from "@/components/dashboard/AttackRateChart";
import { incidentLogs } from "@/lib/mockData"; 

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

       {/* ---------------- 3 กล่องกราฟด้านล่างแผนที่ ---------------- */}
       <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* 1. Session Activity (Area Chart) */}
          <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-5 flex flex-col hover:border-purple-900/50 transition-colors">
             <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-4">Session Activity (24H)</h3>
             <div className="flex-1 min-h-[180px]">
                <AttackRateChart />
             </div>
          </div>

          {/* 2. Status Split (Donut Chart) */}
          <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-3 flex flex-col hover:border-purple-900/50 transition-colors">
             <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-4">Status Split</h3>
             <div className="flex-1 flex flex-col items-center justify-center">
                <div className="h-32 w-full">
                   <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                         <Pie data={statusData} innerRadius={40} outerRadius={55} paddingAngle={4} dataKey="value" stroke="none">
                            {statusData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                         </Pie>
                      </PieChart>
                   </ResponsiveContainer>
                </div>
                {/* Legend ของ Donut Chart */}
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 w-full mt-4">
                   <div className="flex justify-between items-center bg-[#18181b] px-2 py-1 rounded text-[10px]"><span className="text-slate-400">Completed</span><span className="text-white font-mono">45%</span></div>
                   <div className="flex justify-between items-center bg-[#18181b] px-2 py-1 rounded text-[10px]"><span className="text-slate-400">Running</span><span className="text-white font-mono">30%</span></div>
                   <div className="flex justify-between items-center bg-[#18181b] px-2 py-1 rounded text-[10px]"><span className="text-slate-400">Failed</span><span className="text-white font-mono">15%</span></div>
                   <div className="flex justify-between items-center bg-[#18181b] px-2 py-1 rounded text-[10px]"><span className="text-slate-400">Queued</span><span className="text-white font-mono">10%</span></div>
                </div>
             </div>
          </div>

          {/* 3. Tactic Frequency (Horizontal Bars) */}
          <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-4 flex flex-col hover:border-purple-900/50 transition-colors">
             <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-4">Tactic Frequency</h3>
             <div className="flex flex-col gap-3 flex-1 justify-center">
                <TacticBar label="execution" count={128} max={150} color="bg-purple-500" />
                <TacticBar label="reconnaissance" count={94} max={150} color="bg-purple-600" />
                <TacticBar label="credential-access" count={85} max={150} color="bg-purple-700" />
                <TacticBar label="persistence" count={62} max={150} color="bg-purple-800" />
                <TacticBar label="discovery" count={45} max={150} color="bg-slate-600" />
             </div>
          </div>
       </div>

       {/* ---------------- Sessions Table (Live Incident Log) ---------------- */}
       <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden hover:border-purple-900/50 transition-colors">
          <div className="px-6 py-5 border-b border-slate-800/80 flex flex-col sm:flex-row justify-between sm:items-center gap-4">
             <div>
                <h3 className="text-sm font-semibold text-white tracking-tight">Sessions</h3>
                <p className="text-[11px] text-slate-500 mt-0.5">1,248 total · click row for intelligence detail</p>
             </div>
          </div>
          
          <div className="overflow-x-auto">
             <table className="w-full text-left">
                <thead className="bg-[#09090b] border-b border-slate-800/80">
                   <tr className="text-slate-500 text-[10px] uppercase tracking-widest font-semibold">
                      <th className="px-6 py-3">Session ID / IP</th>
                      <th className="px-6 py-3">Status</th>
                      <th className="px-6 py-3">Tactics</th>
                      <th className="px-6 py-3 text-right">Commands</th>
                   </tr>
                </thead>
                <tbody>
                   {incidentLogs.map((log) => (
                      <tr key={log.id} className="border-b border-slate-800/40 hover:bg-slate-800/30 transition-colors cursor-pointer group">
                         <td className="px-6 py-3.5">
                            <div className="font-mono text-xs text-purple-300">{log.sourceIp}</div>
                            <div className="text-[10px] text-slate-500 font-mono mt-0.5">sess_{log.id.toLowerCase()}</div>
                         </td>
                         <td className="px-6 py-3.5">
                            <span className="flex items-center gap-1.5 text-[11px] text-slate-300">
                               <span className={`w-1.5 h-1.5 rounded-full ${log.status === 'Blocked' || log.status === 'Quarantined' ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
                               {log.status === 'Blocked' ? 'Completed' : 'Failed'}
                            </span>
                         </td>
                         <td className="px-6 py-3.5">
                            <span className="bg-[#18181b] border border-slate-700/50 px-2 py-0.5 rounded text-[10px] text-slate-400">{log.type}</span>
                         </td>
                         <td className="px-6 py-3.5 text-right font-mono text-xs text-slate-400">
                            {Math.floor(Math.random() * 50) + 1}
                         </td>
                      </tr>
                   ))}
                </tbody>
             </table>
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