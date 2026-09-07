"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Calendar, Download, Filter, Search, Shield } from "lucide-react";

import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { RegionState } from "@/components/ui/RegionState";
import { SelectMenu } from "@/components/ui/SelectMenu";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

const ITEMS_PER_PAGE = 10;
const initialFilters = { dateRange: "Last 30 Days", attackerType: "All Types", criticality: "All Levels", region: "" };

export default function ArchivesPage() {
  const [sessions, setSessions] = useState<DashboardThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState(initialFilters);
  const [now, setNow] = useState<number | null>(null);

  useEffect(() => {
    const fetchArchive = async () => {
      try {
        const res = await fetch("/api/threats?range=all");
        if (!res.ok) throw new Error("Archive request failed");
        const data: unknown = await res.json();
        if (!Array.isArray(data)) throw new Error("Archive response unavailable");
        setNow(Date.now());
        setSessions(data.filter(isDashboardThreatEvent));
        setFetchFailed(false);
      } catch {
        setFetchFailed(true);
      } finally {
        setLoading(false);
      }
    };
    fetchArchive();
  }, []);

  const filteredSessions = useMemo(() => {
    const normalizedRegion = filters.region.trim().toLowerCase();
    const normalizedType = filters.attackerType === "All Types" ? "" : filters.attackerType.toLowerCase().replace("botnet", "bot").replace("script kiddie", "script");
    const days = filters.dateRange === "Last 30 Days" ? 30 : filters.dateRange === "Last 6 Months" ? 183 : null;
    const cutoff = days && now ? now - days * 24 * 60 * 60 * 1000 : null;

    return sessions.filter((session) => {
      if (normalizedType && !session.classification.toLowerCase().includes(normalizedType)) return false;
      if (filters.criticality !== "All Levels" && session.severity !== filters.criticality) return false;
      if (normalizedRegion && ![session.geo.city, session.geo.country].some((value) => value.toLowerCase().includes(normalizedRegion))) return false;
      if (cutoff !== null) {
        const timestamp = new Date(session.timestamp).getTime();
        if (Number.isFinite(timestamp) && timestamp < cutoff) return false;
      }
      return true;
    });
  }, [filters, now, sessions]);

  const totalPages = Math.max(1, Math.ceil(filteredSessions.length / ITEMS_PER_PAGE));
  const displayPage = Math.min(currentPage, totalPages);
  const currentData = filteredSessions.slice((displayPage - 1) * ITEMS_PER_PAGE, displayPage * ITEMS_PER_PAGE);
  const filtersActive = JSON.stringify(filters) !== JSON.stringify(initialFilters);

  const getPageNumbers = () => {
    let start = Math.max(1, displayPage - 2);
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
  };

  const updateFilter = (key: keyof typeof filters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setCurrentPage(1);
  };

  const handleExport = () => {
    if (!filteredSessions.length) return;
    const escapeCsv = (value: string) => `"${value.replace(/"/g, '""')}"`;
    const rows = [
      ["Session ID", "Timestamp (UTC)", "Origin IP", "Attacker type", "Criticality"],
      ...filteredSessions.map((session) => [session.id, `${session.date} ${session.time}`, session.sourceIp, session.classification, session.severity]),
    ];
    const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `pti-security-archive-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  return (
    <div className="mx-auto max-w-[1400px] space-y-7 pb-8">
      <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Investigation / History</p>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">Security incursion archive</h1>
          <p className="mt-2 text-sm text-text-muted">{filteredSessions.length.toLocaleString()} sessions match the current view.</p>
        </div>
        <button onClick={handleExport} disabled={!filteredSessions.length} className="ui-button ui-button-primary">
          <Download className="h-4 w-4" aria-hidden="true" /> Export archive
        </button>
      </header>

      <section className="ui-panel overflow-hidden" aria-labelledby="archive-title" aria-busy={loading}>
        <div className="space-y-4 border-b border-border bg-surface-subtle p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div><h2 id="archive-title" className="text-base font-semibold">Filter archive</h2><p className="mt-1 text-sm text-text-muted">Filters apply as you change them.</p></div>
            <button type="button" onClick={() => { setFilters(initialFilters); setCurrentPage(1); }} disabled={!filtersActive} className="ui-button min-h-9 px-3 text-xs">
              <Filter className="h-3.5 w-3.5" aria-hidden="true" /> Clear filters
            </button>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="flex flex-col gap-2 text-sm font-medium text-text-muted"><span>Date range</span>
              <SelectMenu value={filters.dateRange} onValueChange={(value) => updateFilter("dateRange", value)} options={["Last 30 Days", "Last 6 Months", "All Time"]} leadingIcon={<Calendar className="h-4 w-4" />} />
            </div>
            <div className="flex flex-col gap-2 text-sm font-medium text-text-muted"><span>Attacker type</span>
              <SelectMenu value={filters.attackerType} onValueChange={(value) => updateFilter("attackerType", value)} options={["All Types", "APT", "Botnet", "Script Kiddie"]} leadingIcon={<Shield className="h-4 w-4" />} />
            </div>
            <div className="flex flex-col gap-2 text-sm font-medium text-text-muted"><span>Criticality</span>
              <SelectMenu value={filters.criticality} onValueChange={(value) => updateFilter("criticality", value)} options={["All Levels", "Critical", "High", "Medium", "Low"]} />
            </div>
            <label className="flex flex-col gap-2 text-sm font-medium text-text-muted">Region
              <span className="relative"><Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-text-subtle" aria-hidden="true" /><input value={filters.region} onChange={(event) => updateFilter("region", event.target.value)} type="search" placeholder="Search region..." className="ui-field pl-9" /></span>
            </label>
          </div>
        </div>

        <div className="ui-scroll-region">
          <table className="ui-table min-w-[980px]">
            <thead><tr><th scope="col">Session ID</th><th scope="col">Timestamp (UTC)</th><th scope="col">Origin IP</th><th scope="col">Attacker type</th><th scope="col">Criticality</th><th scope="col" className="text-right">Actions</th></tr></thead>
            <tbody>
              {loading && Array.from({ length: 6 }, (_, index) => <tr key={`archive-loading-${index}`} aria-hidden="true">{Array.from({ length: 6 }, (_, column) => <td key={column}><div className="ui-skeleton h-4 w-full" /></td>)}</tr>)}
              {!loading && fetchFailed && <tr><td colSpan={6} className="p-4"><RegionState kind="error" title="Archive unavailable" description="The security archive could not be loaded." /></td></tr>}
              {!loading && !fetchFailed && filteredSessions.length === 0 && <tr><td colSpan={6} className="p-4"><RegionState kind="empty" title="No matching sessions" description="Try a different date range or filter." /></td></tr>}
              {!loading && !fetchFailed && currentData.map((session) => (
                <tr key={session.id}>
                  <td className="font-mono text-sm text-primary">{session.id.substring(0, 12).toUpperCase()}{session.id.length > 12 ? "…" : ""}</td>
                  <td className="font-mono text-xs"><div className="text-text">{session.date}</div><div className="mt-1 text-text-subtle">{session.time}</div></td>
                  <td className="font-mono text-sm text-text">{session.sourceIp}</td>
                  <td className="text-text">{session.classification}</td>
                  <td><SeverityBadge severity={session.severity} /></td>
                  <td className="text-right"><Link href={`/threat-intel/${session.id}`} className="ui-button min-h-9 px-3 text-xs text-primary">View details</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {!loading && !fetchFailed && filteredSessions.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border bg-surface-subtle p-4 text-xs text-text-muted">
            <span className="mr-auto">Showing {(displayPage - 1) * ITEMS_PER_PAGE + 1}–{Math.min(displayPage * ITEMS_PER_PAGE, filteredSessions.length)} of {filteredSessions.length.toLocaleString()}</span>
            {totalPages > 1 && <><button disabled={displayPage === 1} onClick={() => setCurrentPage(displayPage - 1)} className="ui-button min-h-9 px-3">Prev</button>{getPageNumbers().map((page) => <button key={page} onClick={() => setCurrentPage(page)} aria-current={displayPage === page ? "page" : undefined} className="ui-button min-h-9 min-w-9 px-2">{page}</button>)}<button disabled={displayPage === totalPages} onClick={() => setCurrentPage(displayPage + 1)} className="ui-button min-h-9 px-3">Next</button></>}
          </div>
        )}
      </section>
    </div>
  );
}
