"use client";
import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import RegionalMap from "@/components/dashboard/RegionalMap";
import { Activity, AlertTriangle, ActivitySquare, Filter, Download, Maximize, Minimize, Globe, Radio } from "lucide-react";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

import { RegionState, RefreshStatus, type RegionStatus } from "@/components/ui/RegionState";
import { classificationBadgeClass } from "@/lib/presentation";

export default function DashboardPage() {
  const [status, setStatus] = useState<RegionStatus>("loading");
  const hasResult = useRef(false);
  const mapPanel = useRef<HTMLDivElement>(null);
  const [sessions, setSessions] = useState<DashboardThreatEvent[]>([]);
  const [stats, setStats] = useState({ total: "-", active: "-", critical: 0, health: "-" });
  const [isFullScreen, setIsFullScreen] = useState(false);

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    const fetchThreats = async () => {
      setStatus(hasResult.current ? "refreshing" : "loading");
      try {
        const res = await fetch("/api/threats");
        if (!res.ok) throw new Error("Threat request failed");
        if (res.ok) {
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            const threats = data.filter(isDashboardThreatEvent);
            const criticalCount = threats.filter((d) => d.severity === 'Critical' || d.severity === 'High').length;

            setStats((prev) => ({
              ...prev,
              total: threats.length > 0 ? threats.length.toString() : "0",
              active: threats.length > 0 ? threats.length.toString() : "0",
              critical: criticalCount,
              health: "99.9%"
            }));
            setSessions(threats);
            hasResult.current = true;
            setStatus("ready");
          } else {
            throw new Error("Threat response unavailable");
          }
        }
      } catch {
        // The API reports the underlying failure server-side. Keep this expected
        // polling failure in the visible region state instead of triggering the
        // Next.js development error overlay on every retry.
        setStatus(hasResult.current ? "stale" : "error");
      }
    };
    fetchThreats();
    const interval = setInterval(fetchThreats, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!isFullScreen) return;
    const panel = mapPanel.current;
    const previous = document.activeElement as HTMLElement | null;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panel?.querySelector<HTMLButtonElement>("button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsFullScreen(false);
      if (event.key !== "Tab") return;
      const controls = panel?.querySelectorAll<HTMLElement>('button:not(:disabled), [tabindex="0"]');
      if (!controls?.length) return;
      const first = controls[0], last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.body.style.overflow = oldOverflow; document.removeEventListener("keydown", onKey); previous?.focus(); };
  }, [isFullScreen]);

  // คำนวณข้อมูลสำหรับแสดงในหน้าปัจจุบัน
  const totalPages = Math.ceil(sessions.length / itemsPerPage);
  const currentData = sessions.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  // สร้างปุ่มเลขหน้า (แสดงสูงสุด 5 หน้าใกล้เคียงเพื่อไม่ให้ล้น)
  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: (end - start) + 1 }, (_, i) => start + i);
  };

  return (
    <div className="space-y-6 pb-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold leading-9 tracking-tight">Overview Dashboard</h1>
          <p className="mt-2 text-base text-text-muted">Real-time session monitoring and threat directory.</p>
        </div>
        <div className="flex flex-col items-start gap-1 sm:items-end">
          <span className="ui-badge border-info-border bg-info-subtle text-info"><Radio className="h-3.5 w-3.5" aria-hidden="true" />Live Feed Active</span>
          <RefreshStatus status={status} />
        </div>
      </div>

      <section aria-label="Overview metrics" aria-busy={status === "loading" || status === "refreshing"} className="grid grid-cols-1 gap-5 sm:grid-cols-3 lg:gap-6">
        {[
          { title: "TOTAL SESSIONS", value: stats.total, icon: ActivitySquare },
          { title: "ACTIVE INCURSIONS", value: stats.active, icon: AlertTriangle },
          { title: "HONEYPOT HEALTH", value: stats.health, icon: Activity },
        ].map(({ title, value, icon: Icon }, index) => (
          <div key={title} className={`ui-panel min-h-40 p-7 ${status === "error" ? "border-danger-border bg-danger-subtle" : ""}`}>
            <div className="mb-5 flex items-center justify-between gap-3">
              <h2 className="text-sm font-semibold tracking-wide text-text-muted">{title}</h2>
              <span className={`grid h-9 w-9 place-items-center rounded-xl border ${index === 1 || status === "error" ? "border-danger-border bg-danger-subtle text-danger" : "border-primary-border bg-primary-subtle text-primary"}`}><Icon className="h-4 w-4 shrink-0" aria-hidden="true" /></span>
            </div>
            {status === "loading" ? <div className="space-y-3" aria-label="Loading metric"><div className="ui-skeleton h-9 w-24" /><div className="ui-skeleton h-4 w-36" /></div> : status === "error" ? <p className="text-[15px] font-medium text-danger">Unavailable · request failed</p> : <>
              <div className="flex flex-wrap items-baseline gap-2 text-[32px] font-semibold leading-10 tabular-nums">{value}{index === 2 && stats.health !== "-" && <span className="text-base font-normal text-text-muted">Uptime</span>}</div>
              {index === 1 && <p className="mt-2 flex items-center gap-2 text-sm text-danger"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />{stats.critical} Critical Severity</p>}
              {index === 2 && <div aria-hidden="true" className="mt-4 h-2 overflow-hidden rounded-full bg-border"><div className="h-full rounded-full bg-primary" style={{ width: stats.health !== "-" ? stats.health : "0%" }} /></div>}
            </>}
          </div>
        ))}
      </section>

      <div ref={mapPanel} role={isFullScreen ? "dialog" : undefined} aria-modal={isFullScreen ? true : undefined} aria-labelledby="distribution-title" className={`ui-panel flex flex-col overflow-hidden ${isFullScreen ? "fixed inset-0 z-[100] h-dvh w-screen rounded-none" : "h-[430px] sm:h-[400px]"}`}>
        <div className="z-10 flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface px-6 py-5">
          <h2 id="distribution-title" className="flex items-center gap-2 text-lg font-semibold"><Globe className="h-5 w-5 text-primary" aria-hidden="true" />Global Attack Distribution</h2>
          <div className="flex flex-wrap items-center gap-4 text-sm text-text-muted">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rotate-45 bg-danger" />Critical</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-info" />Active</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 border border-neutral" />Dormant</span>
            <button onClick={() => setIsFullScreen(!isFullScreen)} className="ui-button" title={isFullScreen ? "Exit Full Screen" : "Full Screen"} aria-label={isFullScreen ? "Exit Full Screen" : "Full Screen"}>
              {isFullScreen ? <Minimize className="h-4 w-4" /> : <Maximize className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="min-h-0 w-full flex-1 bg-surface-subtle"><RegionalMap /></div>
      </div>

      <section className="ui-panel overflow-hidden" aria-labelledby="directory-title" aria-busy={status === "loading" || status === "refreshing"}>
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border bg-surface px-6 py-5">
          <h2 id="directory-title" className="flex items-center gap-2 text-lg font-semibold"><Activity className="h-5 w-5 text-primary" aria-hidden="true" />Live Incursion Directory</h2>
          <div className="flex gap-3">
            <button className="ui-button"><Filter className="h-4 w-4" aria-hidden="true" />Filter</button>
            <button className="ui-button"><Download className="h-4 w-4" aria-hidden="true" />Export</button>
          </div>
        </div>
        <div className="relative h-[420px]">
        <div className="ui-scroll-region h-full" role="region" aria-label="Incursion directory table. Scroll to view all rows and columns." tabIndex={0}>
          <table className="ui-table min-w-[880px]">
            <thead><tr>{["SESSION ID", "ORIGIN IP", "ATTACKER TYPE", "DATE & TIME", "DURATION", "ACTION"].map(label => <th key={label} scope="col" className={label === "ACTION" ? "text-right" : ""}>{label}</th>)}</tr></thead>
            <tbody>
              {status === "loading" && Array.from({ length: 5 }, (_, row) => (
                <tr key={`loading-${row}`} aria-hidden="true">
                  {Array.from({ length: 6 }, (_, column) => <td key={column} className="h-[72px]"><div className="ui-skeleton h-4 w-full" /></td>)}
                </tr>
              ))}
              {currentData.map((session, i) => (
                <tr key={i} className="text-text-muted">
                  <td className="font-mono font-medium"><span className="inline-flex items-center gap-2" title={session.id} tabIndex={0} aria-label={session.id}><span className="h-1.5 w-1.5 shrink-0 rounded-full bg-danger" aria-hidden="true" />{session.id.substring(0, 10).toUpperCase()}...</span></td>
                  <td className="font-mono">{session.ip || session.sourceIp}</td>
                  <td><span className={`ui-badge ${classificationBadgeClass(session.typeColor)}`}>{session.classification}</span></td>
                  <td className="font-mono text-xs"><div>{session.date}</div><div className="mt-1 text-text-subtle">{session.time}</div></td>
                  <td className="font-mono text-xs">{session.duration}</td>
                  <td className="text-right"><Link href={`/threat-intel/${session.id}`} className="ui-button text-xs">View Details</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {status === "loading" && <p className="sr-only" role="status">Loading sessions…</p>}
        <div className="absolute inset-x-0 top-[52px] bottom-0 pointer-events-none [&>div]:h-full">
        {status === "error" && <RegionState kind="error" title="Sessions unavailable" description="We couldn’t load the session directory. The next automatic refresh will try again." />}
        {status !== "loading" && status !== "error" && sessions.length === 0 && <RegionState kind="empty" title="NO ACTIVE SESSIONS" description="No sessions were returned in the last successful response." />}
        </div>
        </div>
        {totalPages > 1 && <nav aria-label="Directory pages" className="flex flex-wrap items-center justify-end gap-2 border-t border-border bg-surface-subtle p-4">
          <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="ui-button text-xs">Prev</button>
          {getPageNumbers().map(pageNum => <button key={pageNum} onClick={() => setCurrentPage(pageNum)} aria-current={currentPage === pageNum ? "page" : undefined} aria-label={`Page ${pageNum}`} className="ui-button text-xs">{pageNum}</button>)}
          <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="ui-button text-xs">Next</button>
        </nav>}
      </section>
    </div>
  );
}
