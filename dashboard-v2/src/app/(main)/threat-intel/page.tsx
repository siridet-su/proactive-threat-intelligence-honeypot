import TargetLandscapeChart from "@/components/threat-intel/TargetLandscapeChart";
import Link from "next/link";

// ข้อมูลจำลองสำหรับตาราง Incursion Log
const incursionLogs = [
  { id: 1, date: "2023-11-24", time: "14:22:01.442", ip: "192.168.44.122", class: "APT", classColor: "text-red-400 bg-red-950/40 border-red-900/50" },
  { id: 2, date: "2023-11-24", time: "14:18:55.201", ip: "84.21.112.5", class: "BOT", classColor: "text-slate-300 bg-slate-800/50 border-slate-700" },
  { id: 3, date: "2023-11-24", time: "13:59:12.871", ip: "45.2.99.111", class: "OTHER", classColor: "text-amber-400 bg-amber-950/40 border-amber-900/50" },
  { id: 4, date: "2023-11-24", time: "13:45:01.002", ip: "103.41.22.9", class: "SCRIPT KIDDIE", classColor: "text-slate-400 bg-slate-900/80 border-slate-700/50" },
];

export default function ThreatIntelPage() {
  return (
    <div className="space-y-8 animate-in fade-in duration-500 pb-10">
      
      {/* ----------------- Top Stat Cards ----------------- */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">TOTAL INCURSIONS</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">42,891</span>
            <span className="text-[10px] text-slate-400">~12%</span>
          </div>
        </div>

        {/* Card 2 */}
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">ACTIVE PROXIES</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">154</span>
            <span className="text-[10px] text-amber-500 font-bold">STABLE</span>
          </div>
        </div>

        {/* Card 3 */}
        <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
          <span className="text-[10px] text-slate-500 tracking-wider mb-2">DETECTION LATENCY</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">12ms</span>
            <span className="text-[10px] text-slate-400">AVG</span>
          </div>
        </div>

        {/* Card 4 - Critical */}
        <div className="bg-[#1a1111] border border-red-900/50 p-5 rounded-xl flex flex-col justify-between relative shadow-[0_0_15px_rgba(153,27,27,0.1)]">
          <span className="text-[10px] text-slate-400 tracking-wider mb-2">CRITICAL ALERTS</span>
          <div className="flex items-center gap-2">
            <span className="text-3xl font-bold text-[#fca5a5]">03</span>
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse mt-1"></span>
          </div>
        </div>
      </div>

      {/* -------------- Middle Section -------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left: Target Landscape */}
        <div className="bg-[#111116] border border-slate-800/50 p-6 rounded-xl flex flex-col">
          <div className="flex justify-between items-center mb-8">
            <h3 className="text-base font-semibold text-white">Target Landscape</h3>
            <span className="text-slate-500 hover:text-slate-300 cursor-pointer text-sm">ⓘ</span>
          </div>
          
          <div className="flex-1 flex flex-col items-center justify-center">
            <div className="relative w-full max-w-[200px] mb-8">
              <div className="absolute inset-0 bg-[#1e1e2d]/40 rounded-xl border border-slate-800/50 scale-90"></div>
              <TargetLandscapeChart />
            </div>

            <div className="grid grid-cols-2 gap-y-3 gap-x-6 w-full text-xs font-mono text-slate-300 px-4">
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#a855f7]"></span>APT (25%)</div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#d946ef]"></span>Bot (45%)</div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#64748b]"></span>Script (20%)</div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#d97706]"></span>Other (10%)</div>
            </div>
          </div>
        </div>

        {/* Right: Live Incursion Log */}
        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/50 rounded-xl flex flex-col overflow-hidden">
          <div className="p-6 border-b border-slate-800/50 flex justify-between items-start">
            <div>
              <h3 className="text-base font-semibold text-white mb-1">Live Incursion Log</h3>
              <p className="text-xs text-slate-500">Real-time packet interception & origin analysis</p>
            </div>
            <button className="bg-purple-200 text-purple-900 font-semibold px-4 py-2 rounded-md text-xs hover:bg-white transition flex items-center gap-2">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
              Export CSV
            </button>
          </div>
          
          <div className="flex-1 overflow-x-auto">
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
                {incursionLogs.map((log) => (
                  <tr key={log.id} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                    <td className="px-6 py-4 font-mono text-[11px] text-slate-400">
                      <div>{log.date}</div>
                      <div className="text-slate-600">{log.time}</div>
                    </td>
                    <td className="px-6 py-4 font-mono text-[#a855f7] text-xs">{log.ip}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 text-[9px] font-bold border rounded-sm flex items-center gap-1.5 w-max ${log.classColor}`}>
                        <span className="w-1 h-1 rounded-full bg-current opacity-70"></span>
                        {log.class}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      {/* แก้ไข 2: แนบ log.id ไปกับ URL เพื่อให้แสดงข้อมูลตรงกับ ID */}
                      <Link 
                        href={`/threat-intel/${log.id}`} 
                        className="border border-slate-700 bg-slate-900/50 text-slate-400 px-3 py-1.5 rounded text-[10px] hover:text-white transition"
                      >
                        View Details ›
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* -------------- Bottom Node Info Section -------------- */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-2">
        <BottomCard 
          title="Top Node" 
          desc="Frankfurt-DE [8.2k hits]" 
          icon={<svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>} 
        />
        <BottomCard 
          title="Protocol Saturation" 
          desc="SSH Brute Force: 68%" 
          icon={<svg className="w-4 h-4 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>} 
          highlightDesc
        />
        <BottomCard 
          title="Legal Action" 
          desc="12 Take-downs initiated" 
          icon={<svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" /></svg>} 
        />
        <BottomCard 
          title="Network Load" 
          desc="Nominal: 4.2 Gbps" 
          icon={<svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>} 
        />
      </div>

    </div>
  );
}

// Sub-component สำหรับการ์ดข้อมูลด้านล่าง
function BottomCard({ title, desc, icon, highlightDesc }: { title: string, desc: string, icon: React.ReactNode, highlightDesc?: boolean }) {
  return (
    <div className="bg-[#111116] border border-slate-800/50 p-4 rounded-xl flex items-center gap-4 relative overflow-hidden group">
      {/* Background Icon (ลายน้ำ) */}
      <div className="absolute right-0 bottom-0 translate-x-1/4 translate-y-1/4 opacity-5 text-slate-400 w-16 h-16 pointer-events-none">
        {icon}
      </div>
      <div className="w-10 h-10 rounded-lg bg-[#1e1e2d] border border-slate-700/50 flex items-center justify-center shrink-0">
        {icon}
      </div>
      <div>
        <h4 className="text-[11px] font-bold text-white mb-0.5">{title}</h4>
        <p className={`text-[10px] font-mono ${highlightDesc ? 'text-amber-500/80' : 'text-slate-400'}`}>{desc}</p>
      </div>
    </div>
  );
}