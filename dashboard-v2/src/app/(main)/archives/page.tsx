"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { Download, Filter, Search, Calendar, Shield, Globe } from "lucide-react";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";
import { classificationBadgeClass } from "@/lib/presentation";

export default function ArchivesPage() {
  const [sessions, setSessions] = useState<DashboardThreatEvent[]>([]);
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
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            setSessions(data.filter(isDashboardThreatEvent));
          }
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
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, i) => start + i);
  };

  return (
    <div className="mx-auto max-w-[1400px] space-y-6 pb-8">

      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Security incursion archive</h1>
          <p className="mt-2 text-sm text-text-muted">Total archived sessions: {sessions.length.toLocaleString()}</p>
        </div>
        <button className="ui-button ui-button-primary">
          <Download className="w-4 h-4" /> Export Archive
        </button>
      </div>

      <div className="ui-panel overflow-hidden">

        {/* Filters Bar */}
        <div className="space-y-4 border-b border-border bg-surface-subtle p-5 sm:p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-text-muted">Date range</label>
              <div className="relative">
                <Calendar className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" />
                <select className="ui-field appearance-none pl-9">
                  <option>Last 30 Days</option>
                  <option>Last 6 Months</option>
                  <option>All Time</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-text-muted">Attacker type</label>
              <div className="relative">
                <Shield className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" />
                <select className="ui-field appearance-none pl-9">
                  <option>All Types</option>
                  <option>APT</option>
                  <option>Botnet</option>
                  <option>Script Kiddie</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-text-muted">Criticality</label>
              <select className="ui-field appearance-none">
                <option>All Levels</option>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-text-muted">Region</label>
              <div className="relative">
                <Globe className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" />
                <input type="text" placeholder="Search region..." className="ui-field pl-9" />
              </div>
            </div>
          </div>

          <button className="ui-button w-max text-xs">
            <Filter className="w-3 h-3" /> Filter
          </button>
        </div>

        {/* Table */}
        <div className="ui-scroll-region min-h-[360px]">
          <table className="ui-table min-w-[900px]">
            <thead>
              <tr>
                <th scope="col">Session ID</th><th scope="col">Timestamp (UTC)</th><th scope="col">Origin IP</th><th scope="col">Attacker type</th><th scope="col">Criticality</th><th scope="col" className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="py-12 text-center text-text-muted">Loading archives...</td></tr>
              ) : currentData.map((session, i) => (
                <tr key={i} className="text-text-muted">
                  <td className="font-mono text-xs">
                    {session.id.substring(0, 10).toUpperCase()}
                  </td>
                  <td className="font-mono text-xs">
                    {session.date} {session.time}
                  </td>
                  <td className="font-mono text-xs text-text">{session.sourceIp}</td>
                  <td><span className="text-xs capitalize text-text">{session.classification.toLowerCase()}</span>
                  </td>
                  <td><span className={`ui-badge ${classificationBadgeClass(session.typeColor)}`}>
                       {session.severity.toUpperCase()}
                     </span>
                  </td>
                  <td className="text-right"><Link href={`/threat-intel/${session.id}`} className="ui-button min-h-9 px-3 text-xs">
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
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-surface-subtle p-4 text-xs text-text-muted">
            <div>
               Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, sessions.length)} of {sessions.length.toLocaleString()} entries
            </div>
            <div className="flex gap-2">
              <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="ui-button min-h-9 px-3">&lt;</button>
              {getPageNumbers().map(pageNum => (
                <button key={pageNum} onClick={() => setCurrentPage(pageNum)} aria-current={currentPage === pageNum ? "page" : undefined} className="ui-button min-h-9 px-3">
                  {pageNum}
                </button>
              ))}
              <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="ui-button min-h-9 px-3">&gt;</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
