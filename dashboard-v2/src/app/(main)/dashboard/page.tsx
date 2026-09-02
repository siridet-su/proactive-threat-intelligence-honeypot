"use client";
import Link from "next/link";
import RegionalMap from "@/components/dashboard/RegionalMap";
import { Activity, AlertTriangle, ActivitySquare, Filter, Download } from "lucide-react";

// Mock Data สำหรับตาราง Live Incursion Directory
const mockSessions = [
  { id: "SID-89A2-FX", ip: "192.168.1.105", type: "APT", typeColor: "bg-red-900/40 text-red-400 border-red-900", time: "14:22:05 UTC", duration: "00:45:12", isLive: true },
  { id: "SID-77B1-ZZ", ip: "45.22.19.10", type: "Bot", typeColor: "bg-slate-800 text-slate-300 border-slate-700", time: "14:15:30 UTC", duration: "00:52:45", isLive: false },
  { id: "SID-11C3-QQ", ip: "89.144.2.55", type: "Script Kiddie", typeColor: "bg-slate-800 text-slate-300 border-slate-700", time: "13:50:11 UTC", duration: "01:18:04", isLive: false },
  { id: "SID-99D4-WW", ip: "10.0.5.221", type: "APT", typeColor: "bg-red-900/40 text-red-400 border-red-900", time: "12:10:00 UTC", duration: "02:58:15", isLive: false },
  { id: "SID-22E5-MM", ip: "172.16.0.44", type: "Bot", typeColor: "bg-slate-800 text-slate-300 border-slate-700", time: "10:05:22 UTC", duration: "05:02:55", isLive: false },
];

export default function DashboardPage() {
  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10 max-w-[1400px] mx-auto">
      
      {/* ---------------- 1. Global Attack Distribution (แผนที่) ---------------- */}
      <div className="bg-[#0f0f13] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg flex flex-col h-[350px]">
        <div className="px-6 py-4 flex justify-between items-center z-10 bg-gradient-to-b from-[#0a0a0c] to-transparent">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-4 h-4 rounded-full bg-purple-900/50 flex items-center justify-center"><span className="w-2 h-2 rounded-full bg-purple-400"></span></span>
            Global Attack Distribution
          </h2>
          <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400"></span>Critical</span>
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-400"></span>Active</span>
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-600"></span>Dormant</span>
          </div>
        </div>
        <div className="flex-1 w-full -mt-12">
           <RegionalMap />
        </div>
      </div>

      {/* Header สำหรับส่วนล่าง */}
      <div className="pt-4 flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white">Overview Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time session monitoring and threat directory.</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
          <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse"></span> Live Feed Active
        </div>
      </div>

      {/* ---------------- 2. Overview Stats ---------------- */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md flex flex-col justify-between">
           <div className="flex justify-between items-start mb-4">
             <span className="text-xs font-mono text-slate-400 tracking-wider">TOTAL SESSIONS</span>
             <ActivitySquare className="w-4 h-4 text-slate-500" />
           </div>
           <div>
             <div className="text-4xl font-bold text-white">14,208</div>
             <div className="text-xs font-mono text-purple-400 mt-2 flex items-center gap-1">
               ↗ +12% from last week
             </div>
           </div>
        </div>

        <div className="bg-[#150e11] border border-red-900/50 rounded-xl p-6 shadow-[0_0_15px_rgba(153,27,27,0.1)] flex flex-col justify-between relative overflow-hidden">
           <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/5 blur-[50px] rounded-full"></div>
           <div className="flex justify-between items-start mb-4 relative z-10">
             <span className="text-xs font-mono text-red-500 tracking-wider font-semibold">ACTIVE INCURSIONS</span>
             <AlertTriangle className="w-4 h-4 text-red-500" />
           </div>
           <div className="relative z-10">
             <div className="text-4xl font-bold text-[#fca5a5]">42</div>
             <div className="text-xs font-mono text-slate-400 mt-2 flex items-center gap-2">
               <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span> 7 Critical Severity
             </div>
           </div>
        </div>

        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md flex flex-col justify-between">
           <div className="flex justify-between items-start mb-4">
             <span className="text-xs font-mono text-slate-400 tracking-wider">HONEYPOT HEALTH</span>
             <Activity className="w-4 h-4 text-slate-500" />
           </div>
           <div>
             <div className="text-4xl font-bold text-white flex items-baseline gap-2">
                98.9% <span className="text-sm font-normal text-slate-400">Uptime</span>
             </div>
             <div className="w-full h-1.5 bg-slate-800 rounded-full mt-4 overflow-hidden">
                <div className="h-full bg-purple-400 rounded-full w-[98.9%] shadow-[0_0_10px_rgba(192,132,252,0.5)]"></div>
             </div>
           </div>
        </div>
      </div>

      {/* ---------------- 3. Live Incursion Directory (Table) ---------------- */}
      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden shadow-xl mt-6">
        <div className="p-5 border-b border-slate-800/80 flex justify-between items-center bg-[#15151c]">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
            <span className="text-purple-400">≡</span> Live Incursion Directory
          </h3>
          <div className="flex gap-3">
             <button className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-800/50 border border-slate-700 px-3 py-1.5 rounded hover:bg-slate-700 transition">
               <Filter className="w-3 h-3" /> Filter
             </button>
             <button className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-800/50 border border-slate-700 px-3 py-1.5 rounded hover:bg-slate-700 transition">
               <Download className="w-3 h-3" /> Export
             </button>
          </div>
        </div>
        
        <table className="w-full text-left text-sm">
          <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50 bg-[#0a0a0c]">
            <tr>
              <th className="px-6 py-4 font-semibold">SESSION ID</th>
              <th className="px-6 py-4 font-semibold">ORIGIN IP</th>
              <th className="px-6 py-4 font-semibold">ATTACKER TYPE</th>
              <th className="px-6 py-4 font-semibold">START TIME</th>
              <th className="px-6 py-4 font-semibold">DURATION</th>
              <th className="px-6 py-4 text-right font-semibold">ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {mockSessions.map((session, i) => (
              <tr key={i} className="hover:bg-slate-800/20 text-slate-300 transition-colors">
                <td className="px-6 py-4 font-mono font-medium flex items-center gap-2">
                  {session.isLive ? <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> : <span className="w-1.5 h-1.5"></span>}
                  {session.id}
                </td>
                <td className="px-6 py-4 font-mono">{session.ip}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-[10px] font-mono font-bold border rounded-sm ${session.typeColor}`}>
                    {session.type}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono text-xs text-slate-400">{session.time}</td>
                <td className="px-6 py-4 font-mono text-xs text-slate-400">{session.duration}</td>
                <td className="px-6 py-4 text-right">
                   {/* ปุ่ม View Details นำทางไปที่หน้า Threat Intel ของ Session นั้นๆ */}
                   <Link 
                     href={`/threat-intel/${session.id}`} 
                     className="text-[10px] font-mono border border-slate-700 bg-slate-900 px-3 py-1.5 rounded hover:text-white hover:border-slate-500 transition-colors"
                   >
                     View Details
                   </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  );
}