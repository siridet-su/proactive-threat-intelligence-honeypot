"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import RegionalMap from "@/components/dashboard/RegionalMap";
import { Activity, AlertTriangle, ActivitySquare, Filter, Download, Maximize, Minimize } from "lucide-react";

export default function DashboardPage() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [stats, setStats] = useState({ total: "-", active: "-", critical: 0, health: "-" });
  const [isFullScreen, setIsFullScreen] = useState(false);
  
  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data = await res.json();
          const criticalCount = data.filter((d: any) => d.severity === 'Critical' || d.severity === 'High').length;
          
          setStats(prev => ({
             ...prev,
             total: data.length > 0 ? data.length.toString() : "0",
             active: data.length > 0 ? data.length.toString() : "0",
             critical: criticalCount,
             health: "99.9%"
          }));
          setSessions(data);
        }
      } catch (err) {
        console.error("Failed to fetch threats:", err);
      }
    };
    fetchThreats();
    const interval = setInterval(fetchThreats, 15000);
    return () => clearInterval(interval);
  }, []);

  // คำนวณข้อมูลสำหรับแสดงในหน้าปัจจุบัน
  const totalPages = Math.ceil(sessions.length / itemsPerPage);
  const currentData = sessions.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  // สร้างปุ่มเลขหน้า (แสดงสูงสุด 5 หน้าใกล้เคียงเพื่อไม่ให้ล้น)
  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: (end - start) + 1 }, (_, i) => start + i);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10 max-w-[1400px] mx-auto">
      {/* 1. Global Attack Distribution */}
      <div 
        className={`bg-[#0f0f13] border border-slate-800/80 overflow-hidden shadow-lg flex flex-col transition-all duration-300 ${
          isFullScreen 
            ? 'fixed inset-0 z-[100] rounded-none h-screen w-screen' 
            : 'rounded-xl h-[350px]'
        }`}
      >
        <div className="px-6 py-4 flex justify-between items-center z-10 bg-gradient-to-b from-[#0a0a0c] to-transparent">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-4 h-4 rounded-full bg-purple-900/50 flex items-center justify-center">
              <span className="w-2 h-2 rounded-full bg-purple-400"></span>
            </span>
            Global Attack Distribution
          </h2>
          <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400"></span>Critical</span>
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-400"></span>Active</span>
             <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-600"></span>Dormant</span>
             
             {/* เส้นคั่นและปุ่ม Full Screen */}
             <div className="w-px h-4 bg-slate-700 mx-1"></div>
             <button 
               onClick={() => setIsFullScreen(!isFullScreen)} 
               className="p-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
               title={isFullScreen ? "Exit Full Screen" : "Full Screen"}
             >
               {isFullScreen ? <Minimize className="w-3.5 h-3.5" /> : <Maximize className="w-3.5 h-3.5" />}
             </button>
          </div>
        </div>
        <div className="flex-1 w-full -mt-12">
           <RegionalMap />
        </div>
      </div>

      {/* Header Overview */}
      <div className="pt-4 flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white">Overview Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time session monitoring and threat directory.</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
          <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse"></span> Live Feed Active
        </div>
      </div>

      {/* 2. Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md flex flex-col justify-between">
           <div className="flex justify-between items-start mb-4">
             <span className="text-xs font-mono text-slate-400 tracking-wider">TOTAL SESSIONS</span>
             <ActivitySquare className="w-4 h-4 text-slate-500" />
           </div>
           <div>
             <div className="text-4xl font-bold text-white">{stats.total}</div>
           </div>
        </div>
        <div className="bg-[#150e11] border border-red-900/50 rounded-xl p-6 shadow-[0_0_15px_rgba(153,27,27,0.1)] flex flex-col justify-between relative overflow-hidden">
           <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/5 blur-[50px] rounded-full"></div>
           <div className="flex justify-between items-start mb-4 relative z-10">
             <span className="text-xs font-mono text-red-500 tracking-wider font-semibold">ACTIVE INCURSIONS</span>
             <AlertTriangle className="w-4 h-4 text-red-500" />
           </div>
           <div className="relative z-10">
             <div className="text-4xl font-bold text-[#fca5a5]">{stats.active}</div>
             <div className="text-xs font-mono text-slate-400 mt-2 flex items-center gap-2">
               <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span> {stats.critical} Critical Severity
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
                {stats.health} {stats.health !== "-" && <span className="text-sm font-normal text-slate-400">Uptime</span>}
             </div>
             <div className="w-full h-1.5 bg-slate-800 rounded-full mt-4 overflow-hidden">
                <div className="h-full bg-purple-400 rounded-full shadow-[0_0_10px_rgba(192,132,252,0.5)]" style={{ width: stats.health !== "-" ? stats.health : "0%" }}></div>
             </div>
           </div>
        </div>
      </div>

      {/* 3. Live Incursion Directory พร้อม Pagination */}
      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden shadow-xl mt-6">
        <div className="p-5 border-b border-slate-800/80 flex justify-between items-center bg-[#15151c]">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
            <span className="text-purple-400">⚡</span> Live Incursion Directory
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
              <th className="px-6 py-4 font-semibold">DATE & TIME</th>
              <th className="px-6 py-4 font-semibold">DURATION</th>
              <th className="px-6 py-4 text-right font-semibold">ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {currentData.map((session, i) => (
              <tr key={i} className="hover:bg-slate-800/20 text-slate-300 transition-colors">
                <td className="px-6 py-4 font-mono font-medium flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
                  {session.id.substring(0, 10).toUpperCase()}...
                </td>
                <td className="px-6 py-4 font-mono">{session.ip || session.sourceIp}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-[10px] font-mono font-bold border rounded-sm ${session.typeColor}`}>
                    {session.classification}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono text-[11px] text-slate-400">
                  <div>{session.date}</div>
                  <div className="text-slate-600">{session.time}</div>
                </td>
                <td className="px-6 py-4 font-mono text-xs text-slate-400">{session.duration}</td>
                <td className="px-6 py-4 text-right">
                   <Link href={`/threat-intel/${session.id}`} className="text-[10px] font-mono border border-slate-700 bg-slate-900 px-3 py-1.5 rounded hover:text-white transition-colors">
                     View Details
                   </Link>
                </td>
              </tr>
            ))}
            {sessions.length === 0 && (
              <tr><td colSpan={6} className="text-center py-8 text-slate-500 font-mono">NO ACTIVE SESSIONS</td></tr>
            )}
          </tbody>
        </table>

        {/* ระบบเปลี่ยนหน้า (Pagination Controls) */}
        {totalPages > 1 && (
          <div className="p-4 border-t border-slate-800/50 bg-[#0a0a0c] flex justify-end items-center gap-2 font-mono text-xs">
            <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50 transition-colors">Prev</button>
            {getPageNumbers().map(pageNum => (
              <button key={pageNum} onClick={() => setCurrentPage(pageNum)} className={`px-3 py-1.5 rounded transition-colors ${currentPage === pageNum ? 'bg-purple-600 text-white font-bold' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}>
                {pageNum}
              </button>
            ))}
            <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50 transition-colors">Next</button>
          </div>
        )}
      </div>
    </div>
  );
}