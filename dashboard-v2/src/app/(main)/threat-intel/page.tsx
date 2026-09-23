"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RefreshStatus, RegionState } from "@/components/ui/RegionState";
// ไม่ต้องใช้ SelectMenu แล้ว เนื่องจากใช้ Native Select แทน
import type {
  DashboardThreatEvent,
  ThreatDirectoryPage,
  ThreatSeverityFilter,
} from "@/lib/dashboardTypes";
import { severityDotClass } from "@/lib/presentation";
import {
  ActivitySquare,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clock,
  Download,
  Radio,
  RefreshCw,
  Search,
  SlidersHorizontal,
  X,
  Database,
  Globe,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

// กำหนด Type ใหม่สำหรับ Attacker Filter
type AttackerTypeFilter = "All" | "APT" | "Bot" | "ScriptKiddie";

const ATTACKER_TYPE_BADGE_CLASS: Record<string, string> = {
  APT: "border-danger-border bg-danger-subtle text-danger",
  ScriptKiddie: "border-warning-border bg-warning-subtle text-warning",
  Bot: "border-border bg-surface-subtle text-text-muted",
};

type RequestStatus = "loading" | "ready" | "error";

// ฟังก์ชันแปลง Attacker Type กลับไปเป็น Severity เพื่อส่งให้ API
const getSeverityFromAttackerType = (type: AttackerTypeFilter): ThreatSeverityFilter => {
  switch (type) {
    case "APT": return "Critical";
    case "Bot": return "High";
    case "ScriptKiddie": return "Medium";
    default: return "All";
  }
};

export default function ThreatIntelPage() {
  const { threats: feedThreats, status, refresh } = useThreatFeed();

  const directoryRequest = useRef(0);
  const directoryRef = useRef<ThreatDirectoryPage | null>(null);
  const directoryLoaderRef = useRef<(background?: boolean) => Promise<void>>(async () => undefined);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [queryInput, setQueryInput] = useState("");
  const query = useDebouncedValue(queryInput, 320);
  
  // เปลี่ยนจาก Severity เป็น Attacker Type
  const [attackerFilter, setAttackerFilter] = useState<AttackerTypeFilter>("All");
  const [filterOpen, setFilterOpen] = useState(false);

  const [directory, setDirectory] = useState<ThreatDirectoryPage | null>(null);
  const [directoryStatus, setDirectoryStatus] = useState<RequestStatus>("loading");
  const [directoryRefreshing, setDirectoryRefreshing] = useState(false);
  const [exportStatus, setExportStatus] = useState<string>("");
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    directoryRef.current = directory;
  }, [directory]);

  const loadDirectory = useCallback(
    async (background = false) => {
      const requestId = directoryRequest.current + 1;
      directoryRequest.current = requestId;
      if (background || directoryRef.current) setDirectoryRefreshing(true);
      else setDirectoryStatus("loading");
      try {
        const params = new URLSearchParams({ page: String(currentPage), pageSize: String(pageSize) });
        if (query) params.set("query", query);
        
        // แปลง Attacker Type เป็น Severity ก่อนยิง API
        const severityParam = getSeverityFromAttackerType(attackerFilter);
        if (severityParam !== "All") params.set("severity", severityParam);
        
        const response = await fetch(`/api/threats/directory?${params}`, { cache: "no-store" });
        if (!response.ok) throw new Error("Threat directory unavailable");
        const data: unknown = await response.json();
        if (!isThreatDirectoryPage(data) || directoryRequest.current !== requestId) return;
        setDirectory(data);
        setDirectoryStatus("ready");
        if (data.page !== currentPage) setCurrentPage(data.page);
      } catch {
        if (directoryRequest.current === requestId) setDirectoryStatus("error");
      } finally {
        if (directoryRequest.current === requestId) setDirectoryRefreshing(false);
      }
    },
    [currentPage, pageSize, query, attackerFilter]
  );

  useEffect(() => {
    directoryLoaderRef.current = loadDirectory;
  }, [loadDirectory]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadDirectory(), 0);
    return () => window.clearTimeout(timer);
  }, [loadDirectory]);

  const directoryItems = directory?.items ?? [];
  const directoryTotal = directory?.total ?? 0;
  const directoryTotalPages = directory?.totalPages ?? 1;
  const isDirectoryInitialLoad = directoryStatus === "loading" && !directory;
  const isDirectoryUnavailable = directoryStatus === "error" && !directory;
  const hasDirectoryRefreshError = directoryStatus === "error" && Boolean(directory);

  const stats = useMemo(() => {
    return {
      total: directoryTotal,
      liveBuffer: feedThreats.length,
      activeSessions: feedThreats.filter((entry) => entry.session_status === "active" || entry.duration === "Active").length,
      uniqueOrigins: new Set(feedThreats.map((entry) => entry.sourceIp)).size,
    };
  }, [directoryTotal, feedThreats]);

  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    const end = Math.min(directoryTotalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
  };

  const handleExport = async () => {
    if (!directoryTotal || isExporting) return;
    setIsExporting(true);
    setExportStatus("Preparing export...");
    try {
      const params = new URLSearchParams();
      if (query) params.set("query", query);
      
      const severityParam = getSeverityFromAttackerType(attackerFilter);
      if (severityParam !== "All") params.set("severity", severityParam);
      
      const response = await fetch(`/api/threats/directory/export?${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error("Export failed");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `pti-threat-directory-${new Date().toISOString().slice(0, 10)}.csv`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setExportStatus("Export downloaded successfully.");
    } catch {
      setExportStatus("Export failed. Please try again.");
    } finally {
      setIsExporting(false);
    }
  };

  const isInitialLoad = status === "loading";
  const isUnavailable = status === "error";

  return (
    <div className="space-y-6 pb-12 font-sans">
      {/* Top Header */}
      <header className="flex flex-col justify-between gap-3 border-b border-border pb-4 sm:flex-row sm:items-end">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-primary">
            <span>Threat Intelligence</span>
            <span className="h-1 w-1 rounded-full bg-border-strong" aria-hidden="true" />
            <span className="inline-flex items-center gap-1.5 text-text-subtle font-normal">
              <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
              Real-time Incursions
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-text sm:text-3xl">Threat Intelligence Console</h1>
          <p className="text-sm text-text-muted">Complete queryable intrusion ledger, session logs, and investigation payloads.</p>
        </div>
        <div className="flex items-center gap-3">
          <RefreshStatus status={status} />
          <button
            type="button"
            onClick={() => {
              void refresh();
              void loadDirectory(true);
            }}
            className="ui-button min-h-9 px-3 text-xs font-medium"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Refresh
          </button>
        </div>
      </header>

      {/* KPI Top Cards */}
      <section aria-label="Threat intelligence overview" aria-busy={isInitialLoad} className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total Incursions" value={stats.total.toLocaleString()} description="All retained directory records" icon={Database} tone="info" loading={isDirectoryInitialLoad} unavailable={isDirectoryUnavailable} />
        <MetricCard label="Live Monitor Feed" value={stats.liveBuffer.toLocaleString()} description="Sessions in real-time buffer" icon={Radio} tone="info" loading={isInitialLoad} unavailable={isUnavailable} />
        <MetricCard label="Active Connections" value={stats.activeSessions.toLocaleString()} description="Currently connected to honeypot" icon={Activity} tone="danger" loading={isInitialLoad} unavailable={isUnavailable} />
        <MetricCard label="Live Origin IPs" value={stats.uniqueOrigins.toLocaleString()} description="Distinct sources in live feed" icon={Globe} tone="warning" loading={isInitialLoad} unavailable={isUnavailable} />
      </section>

      {/* Main Full-Width Incursion Directory Table */}
      <section className="ui-panel overflow-hidden border border-border bg-surface shadow-xs" aria-labelledby="directory-title" aria-busy={isDirectoryInitialLoad || directoryRefreshing}>
        <div className="border-b border-border bg-surface px-5 py-3.5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-info">
                <ActivitySquare className="h-4 w-4" aria-hidden="true" />
                Intrusion Feed &amp; Directory
              </div>
              <h2 id="directory-title" className="flex items-center gap-2 text-base font-semibold text-text">
                Incursion Record Ledger
                {hasDirectoryRefreshError && (
                  <span className="inline-flex items-center gap-1 text-[11px] font-normal text-warning" role="status">
                    <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                    Refresh failed
                  </span>
                )}
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative sm:w-72">
                <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
                <input
                  value={queryInput}
                  onChange={(event) => {
                    setQueryInput(event.target.value);
                    setCurrentPage(1);
                  }}
                  type="search"
                  placeholder="Search IP, Session ID..."
                  className="ui-field h-8 pl-8 pr-7 text-xs font-mono"
                />
                {queryInput && (
                  <button
                    type="button"
                    onClick={() => {
                      setQueryInput("");
                      setCurrentPage(1);
                    }}
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-text-subtle hover:text-text"
                    aria-label="Clear search input"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
              <button
                onClick={() => setFilterOpen((value) => !value)}
                className={cn("ui-button h-8 min-h-8 px-2.5 text-xs", (filterOpen || attackerFilter !== "All") && "border-primary bg-primary-subtle text-primary font-semibold")}
                aria-expanded={filterOpen}
                aria-controls="incursion-filter-panel"
              >
                <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                Filter
                {attackerFilter !== "All" && (
                  <span className="grid h-4 min-w-4 place-items-center rounded-full bg-primary px-1 text-[10px] text-on-primary">
                    1
                  </span>
                )}
              </button>
              <button
                onClick={() => void handleExport()}
                disabled={!directoryTotal || isExporting}
                className="ui-button h-8 min-h-8 px-2.5 text-xs"
                title={exportStatus || "Export directory records to CSV"}
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                {isExporting ? "Exporting..." : "Export"}
              </button>
            </div>
          </div>

          {filterOpen && (
            <div id="incursion-filter-panel" className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs shadow-inner">
              <div className="flex items-center gap-2 text-text-muted">
                <label htmlFor="attacker-filter" className="font-semibold text-text">Attacker Type:</label>
                <select
                  id="attacker-filter"
                  value={attackerFilter}
                  onChange={(e) => {
                    setAttackerFilter(e.target.value as AttackerTypeFilter);
                    setCurrentPage(1);
                  }}
                  className="h-8 cursor-pointer rounded-md border border-border bg-surface px-2.5 py-1 text-xs font-semibold text-text shadow-sm hover:bg-surface-hover focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary min-w-[8rem]"
                >
                  <option value="All">All Types</option>
                  <option value="APT">APT (Advanced)</option>
                  <option value="Bot">Bot (Automated)</option>
                  <option value="ScriptKiddie">Script Kiddie</option>
                </select>
              </div>
              <div className="flex items-center gap-3 text-text-muted">
                <span>Total matching: <strong className="text-text">{directoryTotal.toLocaleString()}</strong></span>
                {(queryInput || attackerFilter !== "All") && (
                  <button
                    onClick={() => {
                      setQueryInput("");
                      setAttackerFilter("All");
                      setCurrentPage(1);
                    }}
                    className="inline-flex items-center gap-1 font-semibold text-primary hover:underline"
                  >
                    <X className="h-3 w-3" aria-hidden="true" />
                    Reset Filters
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        <div>
          {isDirectoryInitialLoad && <DirectorySkeleton />}
          {isDirectoryUnavailable && (
            <div className="p-8 text-center">
              <RegionState kind="error" title="Directory unavailable" description="Failed to retrieve records." />
              <button type="button" onClick={() => void loadDirectory()} className="ui-button text-xs mt-3">
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Retry
              </button>
            </div>
          )}
          {!isDirectoryInitialLoad && !isDirectoryUnavailable && directoryItems.length === 0 && (
            <div className="p-8">
              <RegionState
                kind="empty"
                title="No incursions found"
                description={queryInput || attackerFilter !== "All" ? "Try adjusting your search criteria." : "No intrusion records currently recorded."}
              />
            </div>
          )}
          {!isDirectoryInitialLoad && !isDirectoryUnavailable && directoryItems.length > 0 && (
            <DirectoryResults sessions={directoryItems} />
          )}
        </div>

        {directoryTotal > 0 && directoryTotalPages > 1 && (
          <nav aria-label="Directory pages" className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-surface-subtle/50 px-5 py-2.5 text-xs">
            <div className="flex items-center gap-4">
              <p className="text-text-muted">
                Page <strong className="text-text">{currentPage}</strong> of <strong className="text-text">{directoryTotalPages}</strong> ({directoryTotal.toLocaleString()} sessions)
              </p>
              
              <div className="hidden sm:flex items-center gap-2 border-l border-border pl-4">
                <label htmlFor="rows-per-page" className="text-text-muted">Rows:</label>
                <select
                  id="rows-per-page"
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="h-7 cursor-pointer rounded-md border border-border bg-surface px-2 py-0 text-xs font-semibold text-text shadow-sm hover:bg-surface-hover focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value={15}>15</option>
                  <option value={30}>30</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button type="button" disabled={currentPage === 1} onClick={() => setCurrentPage(1)} className="ui-button h-7 min-h-7 px-2 text-xs" aria-label="First page">
                <ChevronsLeft className="h-3 w-3" aria-hidden="true" />
              </button>
              <button type="button" disabled={currentPage === 1} onClick={() => setCurrentPage((page) => page - 1)} className="ui-button h-7 min-h-7 px-2 text-xs" aria-label="Previous page">
                <ChevronLeft className="h-3 w-3" aria-hidden="true" />
              </button>
              {getPageNumbers().map((pageNumber) => (
                <button
                  type="button"
                  key={pageNumber}
                  onClick={() => setCurrentPage(pageNumber)}
                  aria-current={currentPage === pageNumber ? "page" : undefined}
                  className={cn("ui-button h-7 min-h-7 min-w-7 px-1.5 text-xs", currentPage === pageNumber && "bg-primary text-surface font-semibold")}
                >
                  {pageNumber}
                </button>
              ))}
              <button type="button" disabled={currentPage === directoryTotalPages} onClick={() => setCurrentPage((page) => page + 1)} className="ui-button h-7 min-h-7 px-2 text-xs" aria-label="Next page">
                <ChevronRight className="h-3 w-3" aria-hidden="true" />
              </button>
              <button type="button" disabled={currentPage === directoryTotalPages} onClick={() => setCurrentPage(directoryTotalPages)} className="ui-button h-7 min-h-7 px-2 text-xs" aria-label="Last page">
                <ChevronsRight className="h-3 w-3" aria-hidden="true" />
              </button>
            </div>
          </nav>
        )}
      </section>
    </div>
  );
}

function MetricCard({ label, value, description, icon: Icon, tone = "info", loading, unavailable }: { label: string; value: string; description: string; icon: React.ComponentType<{ className?: string }>; tone?: "info" | "warning" | "danger" | "success"; loading: boolean; unavailable: boolean }) {
  return (
    <div className="ui-panel flex items-center gap-4 p-4 border border-border bg-surface transition-colors hover:bg-surface-hover/40 shadow-xs">
      <span className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-border/80", tone === "danger" ? "border-danger-border bg-danger-subtle text-danger" : tone === "warning" ? "border-warning-border bg-warning-subtle text-warning" : tone === "success" ? "border-success-border bg-success-subtle text-success" : "border-info-border bg-info-subtle text-info")}>
        <Icon className="h-5 w-5" aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1">
        <span className="text-xs font-medium text-text-muted">{label}</span>
        {loading ? (
          <div className="mt-1 space-y-1"><div className="ui-skeleton h-5 w-16" /></div>
        ) : unavailable ? (
          <div className="mt-1 flex items-center gap-1.5 text-xs text-danger font-medium"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />Unavailable</div>
        ) : (
          <>
            <div className={cn("mt-0.5 text-2xl font-bold leading-none tabular-nums tracking-tight", tone === "danger" ? "text-danger" : "text-text")}>{value}</div>
            <p className="mt-1 text-xs text-text-subtle truncate">{description}</p>
          </>
        )}
      </div>
    </div>
  );
}

function DirectorySkeleton() {
  return (
    <div className="divide-y divide-border">
      {Array.from({ length: 5 }, (_, row) => (
        <div key={row} className="flex items-center justify-between px-6 py-3">
          <div className="ui-skeleton h-4 w-28" />
          <div className="ui-skeleton h-4 w-24" />
          <div className="ui-skeleton h-4 w-32" />
          <div className="ui-skeleton h-4 w-24" />
          <div className="ui-skeleton h-6 w-16 rounded-md" />
        </div>
      ))}
    </div>
  );
}

function DirectoryResults({ sessions }: { sessions: DashboardThreatEvent[] }) {
  const router = useRouter();

  return (
    <div className="hidden md:block">
      <table className="ui-table w-full text-xs">
        <thead>
          <tr className="border-b border-border bg-surface-subtle/50 text-text-muted font-semibold">
            <th scope="col" className="py-2.5 px-6 text-left w-[240px]">Session ID</th>
            <th scope="col" className="py-2.5 px-6 text-left w-[180px]">Origin IP</th>
            <th scope="col" className="py-2.5 px-6 text-left w-[200px]">Timestamp (UTC)</th>
            <th scope="col" className="py-2.5 px-6 text-left">Attacker Type</th>
            <th scope="col" className="py-2.5 px-6 text-right w-[100px]">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/60 cursor-pointer">
          {sessions.map((session) => {
            const classificationFormat = session.classification.toUpperCase() === "APT" ? "APT" :
                                         session.classification.toUpperCase() === "BOT" ? "Bot" :
                                         "ScriptKiddie";

            return (
              <tr 
                key={session.id} 
                onClick={() => router.push(`/threat-intel/${session.id}`)}
                className="transition-colors hover:bg-surface-hover group"
                title="Click to view details"
              >
                <td className="py-2.5 px-6 font-mono font-medium text-text group-hover:text-primary transition-colors">
                  <span className="inline-flex items-center gap-2">
                    <span className={cn("h-2 w-2 shrink-0 rounded-full", severityDotClass(session.severity))} aria-hidden="true" />
                    <span>{session.id.length > 14 ? `${session.id.substring(0, 12)}...` : session.id}</span>
                  </span>
                </td>
                <td className="py-2.5 px-6 font-mono font-medium text-primary">{session.sourceIp}</td>
                <td className="py-2.5 px-6 text-text-muted">
                  <span className="text-text font-medium">{session.date}</span>{" "}
                  <span className="text-text-subtle font-mono text-[11px]">{session.time}</span>
                </td>
                <td className="py-2.5 px-6">
                  <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border", ATTACKER_TYPE_BADGE_CLASS[classificationFormat] ?? "border-border bg-surface-subtle text-text-muted")}>
                    {session.classification}
                  </span>
                </td>
                <td className="py-2.5 px-6 text-right">
                  <span className="rounded border border-border/70 bg-surface-subtle px-2 py-0.5 text-[11px] text-text-muted">
                    {session.duration}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function useDebouncedValue(value: string, delay: number) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedValue(value), delay);
    return () => window.clearTimeout(timer);
  }, [delay, value]);
  return debouncedValue;
}

function isThreatDirectoryPage(value: unknown): value is ThreatDirectoryPage {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const page = value as Record<string, unknown>;
  return Array.isArray(page.items) && typeof page.page === "number" && typeof page.pageSize === "number" && typeof page.total === "number" && typeof page.totalPages === "number";
}
