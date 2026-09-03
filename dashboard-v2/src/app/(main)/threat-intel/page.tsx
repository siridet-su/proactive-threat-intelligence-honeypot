"use client";
import { useState, useEffect } from "react";
import TargetLandscapeChart from "@/components/threat-intel/TargetLandscapeChart";
import Link from "next/link";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { DashboardChartDatum, DashboardThreatEvent } from "@/lib/dashboardTypes";

export default function ThreatIntelPage() {
  const [logs, setLogs] = useState<DashboardThreatEvent[]>([]);
  const [stats, setStats] = useState({ total: 0, proxies: 0, critical: 0 });
  const [chartData, setChartData] = useState<DashboardChartDatum[]>([]);
  
  // กำหนดให้แสดงสูงสุด 5 รายการต่อหน้า
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5; 

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data: unknown = await res.json();
          if (!Array.isArray(data)) return;
          const threats = data.filter(isDashboardThreatEvent);

          // คำนวณสถิติภาพรวม
          setStats({
            total: threats.length,
            proxies: threats.filter((d) => d.classification === 'BOT').length,
            critical: threats.filter((d) => d.severity === 'Critical' || d.severity === 'High').length
          });
          setLogs(threats);

          // คำนวณข้อมูลจริงสำหรับ Target Landscape
          const aptCount = threats.filter((d) => d.classification === 'APT').length;
          const botCount = threats.filter((d) => d.classification === 'BOT').length;
          const scriptCount = threats.filter((d) => d.classification === 'SCRIPT KIDDIE').length;
          const otherCount = threats.length - (aptCount + botCount + scriptCount);

          setChartData([
            { name: "APT", value: aptCount, color: "#a855f7" },
            { name: "Bot", value: botCount, color: "#d946ef" },
            { name: "Script", value: scriptCount, color: "#64748b" },
            { name: "Other", value: otherCount, color: "#d97706" }
          ]);
        }
      } catch (err) {
        console.error("Failed to fetch threats", err);
      }
    };
    fetchThreats();
    const interval = setInterval(fetchThreats, 15000);
    return () => clearInterval(interval);
  }, []);

  const totalPages = Math.ceil(logs.length / itemsPerPage);
  const currentLogs = logs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, i) => start + i);
  };

  // ใช้ข้อมูลเปอร์เซ็นต์จริงสำหรับแสดงคำบรรยายใต้แผนภูมิ
  const getPercent = (val: number) => stats.total > 0 ? Math.round((val / stats.total) * 100) : 0;

  return (
    <div className="space-y-8 animate-in fade-in duration-500 pb-10">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">TOTAL SESSIONS</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">{stats.total.toLocaleString()}</span>
          </div>
        </div>
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">AUTOMATED BOTS</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">{stats.proxies}</span>
            <span className="text-[10px] text-amber-500 font-bold">DETECTED</span>
          </div>
        </div>
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">DETECTION LATENCY</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">12ms</span>
            <span className="text-[10px] text-slate-400">AVG</span>
          </div>
        </div>
        <div className="bg-[#1a1111] border border-red-900/50 p-5 rounded-xl flex flex-col justify-between relative shadow-[0_0_15px_rgba(153,27,27,0.1)]">
          <span className="text-[10px] text-slate-400 tracking-wider mb-2">CRITICAL THREATS</span>
          <div className="flex items-center gap-2">
            <span className="text-3xl font-bold text-[#fca5a5]">{(stats.critical).toString().padStart(2, '0')}</span>
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse mt-1"></span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#111116] border border-slate-800/50 p-6 rounded-xl flex flex-col h-fit">
          <div className="flex justify-between items-center mb-8">
            <h3 className="text-base font-semibold text-white">Target Landscape</h3>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center">
            <div className="relative w-full max-w-[200px] mb-8">
              <div className="absolute inset-0 bg-[#1e1e2d]/40 rounded-xl border border-slate-800/50 scale-90"></div>
              {/* ส่งข้อมูลจริงไปยัง Chart */}
              <TargetLandscapeChart data={chartData} total={stats.total} />
            </div>
            
            {/* แสดงค่าเปอร์เซ็นต์จริงใต้แผนภูมิ */}
            <div className="grid grid-cols-2 gap-y-3 gap-x-6 w-full text-xs font-mono text-slate-300 px-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#a855f7]"></span>APT ({chartData[0]?.value ? getPercent(chartData[0].value) : 0}%)
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#d946ef]"></span>Bot ({chartData[1]?.value ? getPercent(chartData[1].value) : 0}%)
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#64748b]"></span>Script ({chartData[2]?.value ? getPercent(chartData[2].value) : 0}%)
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#d97706]"></span>Other ({chartData[3]?.value ? getPercent(chartData[3].value) : 0}%)
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/50 rounded-xl flex flex-col overflow-hidden">
          <div className="p-6 border-b border-slate-800/50 flex justify-between items-start">
            <div>
              <h3 className="text-base font-semibold text-white mb-1">Live Incursion Log</h3>
              <p className="text-xs text-slate-500">Real-time packet interception & origin analysis</p>
            </div>
          </div>
          
          <div className="flex-1 flex flex-col justify-between overflow-x-auto min-h-[500px]">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50">
                <tr>
                  <th className="px-6 py-4 font-normal">TIMESTAMP</th>
                  <th className="px-6 py-4 font-normal">HACKER IP</th>
                  <th className="px-6 py-4 font-normal">CLASSIFICATION</th>
                  <th className="px-6 py-4 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody>
                {currentLogs.map((log) => (
                  <tr key={log.id} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors h-[65px]">
                    <td className="px-6 py-2 font-mono text-[11px] text-slate-400">
                      <div>{log.date}</div>
                      <div className="text-slate-600">{log.time}</div>
                    </td>
                    <td className="px-6 py-2 font-mono text-[#a855f7] text-xs">{log.sourceIp}</td>
                    <td className="px-6 py-2">
                      <span className={`px-2 py-1 text-[9px] font-bold border rounded-sm flex items-center gap-1.5 w-max ${log.typeColor}`}>
                        {log.classification}
                      </span>
                    </td>
                    <td className="px-6 py-2 text-right">
                      <Link href={`/threat-intel/${log.id}`} className="border border-slate-700 bg-slate-900/50 text-slate-400 px-3 py-1.5 rounded text-[10px] hover:text-white transition">
                        View Details
                      </Link>
                    </td>
                  </tr>
                ))}
                {/* สร้างช่องว่างให้เต็ม 5 แถวเสมอเมื่อข้อมูลหน้าสุดท้ายไม่ถึง 5 รายการ */}
                {Array.from({ length: Math.max(0, itemsPerPage - currentLogs.length) }).map((_, idx) => (
                  <tr key={`empty-${idx}`} className="h-[65px]">
                    <td colSpan={4}></td>
                  </tr>
                ))}
              </tbody>
            </table>
            
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
      </div>
    </div>
  );
}