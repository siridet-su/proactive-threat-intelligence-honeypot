"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { Download, Filter, Search, Calendar, Shield, Globe } from "lucide-react";

export default function ArchivesPage() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  // Filter State (สำหรับการพัฒนาต่อยอด)
  const [filters, setFilters] = useState({ dateRange: 'Last 30 Days', attackerType: 'All Types', criticality: 'All Levels', region: '' });

  useEffect(() => {
    const fetchArchive = async () => {
      try {
        // ดึงข้อมูลทั้งหมดโดยส่ง range=all
        const res = await fetch("/api/threats?range=all");
        if (res.ok) {
          const data = await res.json();
          setSessions(data);
        }
      } catch (err) {
        console.error("Failed to fetch archive:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchArchive();
  }, []);

  const totalPages = Math.ceil(sessions.length / itemsPerPage);
  const currentData = sessions.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, i) => start + i);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10 max-w-[1400px] mx-auto">
      
      {/* Header */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Incursion Archive</h1>
          <p className="text-slate-400 text-sm">Total Archived Sessions: {sessions.length.toLocaleString()}</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white rounded-md text-sm transition-colors">
          <Download className="w-4 h-4" /> Export Archive
        </button>
      </div>

      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        
        {/* Filters Bar */}
        <div className="p-5 border-b border-slate-800/80 bg-[#15151c] space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-500 font-mono uppercase">Date Range</label>
              <div className="relative">
                <Calendar className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <select className="w-full bg-[#0a0a0c] border border-slate-800 rounded-md pl-9 pr-3 py-2 text-sm text-slate-300 appearance-none focus:outline-none focus:border-purple-500">
                  <option>Last 30 Days</option>
                  <option>Last 6 Months</option>
                  <option>All Time</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-500 font-mono uppercase">Attacker Type</label>
              <div className="relative">
                <Shield className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <select className="w-full bg-[#0a0a0c] border border-slate-800 rounded-md pl-9 pr-3 py-2 text-sm text-slate-300 appearance-none focus:outline-none focus:border-purple-500">
                  <option>All Types</option>
                  <option>APT</option>
                  <option>Botnet</option>
                  <option>Script Kiddie</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-500 font-mono uppercase">Criticality</label>
              <select className="w-full bg-[#0a0a0c] border border-slate-800 rounded-md px-3 py-2 text-sm text-slate-300 appearance-none focus:outline-none focus:border-purple-500">
                <option>All Levels</option>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-500 font-mono uppercase">Region</label>
              <div className="relative">
                <Globe className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input type="text" placeholder="Search region..." className="w-full bg-[#0a0a0c] border border-slate-800 rounded-md pl-9 pr-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-purple-500" />
              </div>
            </div>
          </div>
          
          <button className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-800/50 border border-slate-700 px-4 py-2 rounded hover:bg-slate-700 transition w-max">
            <Filter className="w-3 h-3" /> Filter
          </button>
        </div>
        
        {/* Table */}
        <div className="overflow-x-auto min-h-[400px]">
          <table className="w-full text-left text-sm">
            <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50 bg-[#0a0a0c]">
              <tr>
                <th className="px-6 py-4 font-semibold">SESSION ID</th>
                <th className="px-6 py-4 font-semibold">TIMESTAMP (UTC)</th>
                <th className="px-6 py-4 font-semibold">ORIGIN IP</th>
                <th className="px-6 py-4 font-semibold">ATTACKER TYPE</th>
                <th className="px-6 py-4 font-semibold">CRITICALITY</th>
                <th className="px-6 py-4 text-right font-semibold">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {loading ? (
                <tr><td colSpan={6} className="text-center py-12 text-slate-500">Loading archives...</td></tr>
              ) : currentData.map((session, i) => (
                <tr key={i} className="hover:bg-slate-800/20 text-slate-300 transition-colors h-[60px]">
                  <td className="px-6 py-3 font-mono text-slate-400">
                    {session.id.substring(0, 10).toUpperCase()}
                  </td>
                  <td className="px-6 py-3 font-mono text-[11px] text-slate-400">
                    {session.date} {session.time}
                  </td>
                  <td className="px-6 py-3 font-mono text-slate-300">{session.sourceIp}</td>
                  <td className="px-6 py-3">
                    <span className="text-xs text-slate-300 capitalize">{session.classification.toLowerCase()}</span>
                  </td>
                  <td className="px-6 py-3">
                     <span className={`px-2 py-1 text-[9px] font-mono font-bold border rounded flex items-center gap-1.5 w-max ${
                        session.severity === 'Critical' ? 'bg-red-950/40 text-red-400 border-red-900' : 
                        session.severity === 'High' ? 'bg-orange-950/40 text-orange-400 border-orange-900' : 
                        'bg-slate-800 text-slate-400 border-slate-700'
                     }`}>
                       {session.severity === 'Critical' && <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>}
                       {session.severity.toUpperCase()}
                     </span>
                  </td>
                  <td className="px-6 py-3 text-right">
                     <Link href={`/threat-intel/${session.id}`} className="text-[11px] text-slate-400 hover:text-white transition-colors">
                       View
                     </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 0 && (
          <div className="p-4 border-t border-slate-800/50 bg-[#15151c] flex justify-between items-center text-xs font-mono text-slate-500">
            <div>
               Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, sessions.length)} of {sessions.length.toLocaleString()} entries
            </div>
            <div className="flex gap-1">
              <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="px-3 py-1.5 bg-[#0a0a0c] border border-slate-800 text-slate-400 rounded hover:bg-slate-800 disabled:opacity-50 transition-colors">&lt;</button>
              {getPageNumbers().map(pageNum => (
                <button key={pageNum} onClick={() => setCurrentPage(pageNum)} className={`px-3 py-1.5 rounded transition-colors ${currentPage === pageNum ? 'bg-purple-700 text-white font-bold' : 'bg-[#0a0a0c] border border-slate-800 text-slate-400 hover:bg-slate-800'}`}>
                  {pageNum}
                </button>
              ))}
              <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="px-3 py-1.5 bg-[#0a0a0c] border border-slate-800 text-slate-400 rounded hover:bg-slate-800 disabled:opacity-50 transition-colors">&gt;</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}