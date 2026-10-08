"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RefreshStatus, RegionState } from "@/components/ui/RegionState";
import type {
  ThreatDirectoryPage,
} from "@/lib/dashboardTypes";
import {
  ActivitySquare,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Download,
  RefreshCw,
  Search,
  X,
  Database,
  Globe,
  Activity,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { groupWebHttpSessions, type WebHttpHint, type WebHttpSession } from "@/lib/web-http-intel";
import {
  attackerTypeQueryValue,
  buildSessionDirectoryRows,
  SESSION_ATTACKER_TYPE_OPTIONS,
  type SessionAttackerTypeFilter,
  type SessionAttackerType,
  type SessionDirectoryRow,
  type SessionProtocolFilter,
} from "@/lib/threat-intel-session-directory";

type RequestStatus = "loading" | "ready" | "error";

export default function ThreatIntelPage() {
  const { threats: feedThreats, status, refresh } = useThreatFeed();

  const directoryRequest = useRef(0);
  const directoryRef = useRef<ThreatDirectoryPage | null>(null);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [queryInput, setQueryInput] = useState("");
  const query = useDebouncedValue(queryInput, 320);
  const [protocolFilter, setProtocolFilter] = useState<SessionProtocolFilter>("all");
  const [attackerTypeFilter, setAttackerTypeFilter] = useState<SessionAttackerTypeFilter>("All");

  const [directory, setDirectory] = useState<ThreatDirectoryPage | null>(null);
  const [directoryStatus, setDirectoryStatus] = useState<RequestStatus>("loading");
  const [directoryRefreshing, setDirectoryRefreshing] = useState(false);
  const [isPageChanging, setIsPageChanging] = useState(false);
  const [exportStatus, setExportStatus] = useState<string>("");
  const [isExporting, setIsExporting] = useState(false);
  const [httpItems, setHttpItems] = useState<WebHttpHint[] | null>(null);
  const [httpError, setHttpError] = useState(false);

  const loadHttp = useCallback(async (signal?: AbortSignal) => {
    try {
      const response = await fetch("/api/http-activity", { cache: "no-store", signal });
      if (!response.ok) throw new Error("HTTP feed unavailable");
      const payload: unknown = await response.json();
      if (!payload || typeof payload !== "object" || !Array.isArray((payload as { items?: unknown }).items)) throw new Error("Invalid HTTP feed");
      if (!signal?.aborted) { setHttpItems((payload as { items: WebHttpHint[] }).items); setHttpError(false); }
    } catch { if (!signal?.aborted) setHttpError(true); }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void loadHttp(controller.signal), 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [loadHttp]);

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
        const attackerType = attackerTypeQueryValue(protocolFilter, attackerTypeFilter);
        if (attackerType) params.set("attackerType", attackerType);
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
        if (directoryRequest.current === requestId) {
          setDirectoryRefreshing(false);
          setIsPageChanging(false);
        }
      }
    },
    [attackerTypeFilter, currentPage, pageSize, protocolFilter, query]
  );

  useEffect(() => {
    const timer = window.setTimeout(() => void loadDirectory(), 0);
    return () => window.clearTimeout(timer);
  }, [loadDirectory]);

  const directoryItems = useMemo(() => directory?.items ?? [], [directory?.items]);
  const directoryTotal = directory?.total ?? 0;
  const directoryTotalPages = directory?.totalPages ?? 1;
  const isDirectoryInitialLoad = (directoryStatus === "loading" && !directory) || isPageChanging;
  const isDirectoryUnavailable = directoryStatus === "error" && !directory;
  const hasDirectoryRefreshError = directoryStatus === "error" && Boolean(directory);

  const httpSessions = useMemo(
    () => (httpItems ? groupWebHttpSessions(httpItems).filter((item): item is WebHttpSession & { id: string } => typeof item.id === "string") : []),
    [httpItems],
  );
  const sessionRows = useMemo(
    () => buildSessionDirectoryRows(directoryItems, httpSessions, protocolFilter, queryInput),
    [directoryItems, httpSessions, protocolFilter, queryInput],
  );
  const matchingHttpCount = useMemo(
    () => buildSessionDirectoryRows([], httpSessions, "http", queryInput).length,
    [httpSessions, queryInput],
  );

  const stats = useMemo(() => {
    return {
      total: directoryTotal,
      httpSessions: httpSessions.length,
      activeSessions: feedThreats.filter((entry) => entry.session_status === "active" || entry.duration === "Active").length,
      uniqueOrigins: new Set(feedThreats.map((entry) => entry.sourceIp)).size,
    };
  }, [directoryTotal, feedThreats, httpSessions.length]);

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
      const attackerType = attackerTypeQueryValue(protocolFilter, attackerTypeFilter);
      if (attackerType) params.set("attackerType", attackerType);
      
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
  const isSshDirectoryBusy = protocolFilter !== "http" && (isDirectoryInitialLoad || directoryRefreshing);
  const isHttpDirectoryBusy = protocolFilter !== "ssh" && !httpItems && !httpError;
  const isDirectoryBusy = isSshDirectoryBusy || isHttpDirectoryBusy;
  const shouldShowDirectorySkeleton = sessionRows.length === 0 && isDirectoryBusy;

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
          <p className="text-sm text-text-muted">Browse Cowrie SSH/Telnet and HTTP interactions together, then open protocol-specific session evidence.</p>
        </div>
        <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap sm:flex-nowrap">
          <RefreshStatus status={status} />
          <button
            type="button"
            onClick={() => {
              void refresh();
              void loadDirectory(true);
              void loadHttp();
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
        <MetricCard label="Cowrie Sessions" value={stats.total.toLocaleString()} description="Retained SSH and Telnet sessions" icon={Database} tone="info" loading={isDirectoryInitialLoad} unavailable={isDirectoryUnavailable} />
        <MetricCard label="HTTP Sessions" value={stats.httpSessions.toLocaleString()} description="Grouped from the latest 50 HTTP events" icon={Globe} tone="warning" loading={!httpItems && !httpError} unavailable={httpError} />
        <MetricCard label="Active Connections" value={stats.activeSessions.toLocaleString()} description="Currently connected to honeypot" icon={Activity} tone="danger" loading={isInitialLoad} unavailable={isUnavailable} />
        <MetricCard label="Live Origin IPs" value={stats.uniqueOrigins.toLocaleString()} description="Distinct sources in live feed" icon={Globe} tone="warning" loading={isInitialLoad} unavailable={isUnavailable} />
      </section>

      {/* One protocol-aware directory for all session discovery. */}
      <section className="ui-panel overflow-hidden border border-border bg-surface shadow-xs" aria-labelledby="directory-title" aria-busy={isDirectoryBusy}>
        <div className="border-b border-border bg-surface px-5 py-3.5">
          <div className="flex flex-col gap-3">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#18227A]">
                <ActivitySquare className="h-4 w-4" aria-hidden="true" />
                Session Directory
              </div>
              <h2 id="directory-title" className="mt-1 flex items-center gap-2 text-base font-semibold text-text">
                Sessions that interacted with the honeypot
                {hasDirectoryRefreshError && (
                  <span className="inline-flex items-center gap-1 text-[11px] font-normal text-warning" role="status">
                    <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                    Refresh failed
                  </span>
                )}
              </h2>
            </div>

            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div role="group" aria-label="Session protocol filter" className="inline-flex w-fit rounded-lg border border-[#18227A]/20 bg-surface-subtle p-1">
                {([
                  { id: "all", label: "All", count: directory ? `${(directoryTotal + matchingHttpCount).toLocaleString()}+` : "—", title: "Cowrie total plus HTTP sessions represented in the latest 50 request events" },
                  { id: "ssh", label: "Cowrie", count: directory ? directoryTotal.toLocaleString() : "—", title: "Matching retained Cowrie SSH and Telnet sessions" },
                  { id: "http", label: "HTTP", count: httpItems ? `${matchingHttpCount} recent` : "—", title: "Cookie sessions grouped from the latest 50 stored HTTP events" },
                ] as const).map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    aria-pressed={protocolFilter === tab.id}
                    title={tab.title}
                    onClick={() => {
                      setProtocolFilter(tab.id);
                      if (tab.id !== "ssh") setAttackerTypeFilter("All");
                      if (currentPage !== 1) {
                        setIsPageChanging(true);
                        setCurrentPage(1);
                      }
                    }}
                    className={cn(
                      "inline-flex min-h-8 items-center gap-2 rounded-md px-3 text-xs font-semibold transition-colors",
                      protocolFilter === tab.id
                        ? "bg-primary text-on-primary shadow-xs"
                        : "text-[#18227A] hover:bg-surface-hover",
                    )}
                  >
                    {tab.label}
                    <span className={cn("rounded px-1.5 py-0.5 text-[10px] tabular-nums", protocolFilter === tab.id ? "bg-white/20" : "bg-white text-text-muted")}>
                      {tab.count}
                    </span>
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[15rem] flex-1 sm:flex-none sm:w-72">
                  <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
                  <input
                    value={queryInput}
                    onChange={(event) => {
                      setQueryInput(event.target.value);
                      setCurrentPage(1);
                    }}
                    type="search"
                    placeholder="Search IP, session ID, request path…"
                    className="ui-field h-8 w-full pl-8 pr-7 text-xs font-mono"
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
                {protocolFilter === "ssh" && (
                  <div className="flex h-8 items-center gap-2 rounded-md border border-border bg-surface px-2.5">
                    <label htmlFor="session-attacker-type" className="whitespace-nowrap text-[10px] font-semibold uppercase tracking-wide text-text-muted">Attacker type</label>
                    <select
                      id="session-attacker-type"
                      aria-label="Filter Cowrie sessions by attacker type"
                      value={attackerTypeFilter}
                      onChange={(event) => {
                        setAttackerTypeFilter(event.target.value as SessionAttackerTypeFilter);
                        setCurrentPage(1);
                      }}
                      className="h-full min-w-24 border-0 bg-transparent p-0 text-xs font-semibold text-[#18227A] focus:outline-none focus:ring-0"
                    >
                      <option value="All">All types</option>
                      {SESSION_ATTACKER_TYPE_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </div>
                )}
                <Link href="/http-activity" className="ui-button h-8 min-h-8 px-2.5 text-xs">Request activity</Link>
                {protocolFilter === "ssh" && (
                  <button
                    onClick={() => void handleExport()}
                    disabled={!directoryTotal || isExporting}
                    className="ui-button h-8 min-h-8 px-2.5 text-xs"
                    title={exportStatus || "Export matching Cowrie session records to CSV"}
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" />
                    {isExporting ? "Exporting..." : "Export Cowrie"}
                  </button>
                )}
              </div>
            </div>

            <p className="text-xs leading-5 text-text-muted">
              {protocolFilter === "all"
                ? "All combines each paginated Cowrie result page with HTTP sessions represented in the latest 50 request events. The recent HTTP window stays pinned while you browse Cowrie history."
                : protocolFilter === "ssh"
                  ? "Cowrie sessions are server-searched and paginated. Command counts are shown only where session-bound data is available."
                  : "HTTP sessions are grouped by browser-cookie continuity and cover the latest 50 stored events; this does not verify attacker identity."}
            </p>
          </div>
        </div>

        {/* Scanning Laser Bar when loading / refreshing / page changing */}
        <div className="h-0.5 w-full bg-border/40 overflow-hidden relative">
          {(isDirectoryBusy || isPageChanging) && (
            <div
              className="absolute inset-y-0 w-56 bg-gradient-to-r from-transparent via-primary to-transparent"
              style={{
                animation: "pti-laser-scan 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
              }}
            />
          )}
        </div>

        <div>
          {protocolFilter !== "http" && isDirectoryUnavailable && (
            <p role="alert" className="border-b border-warning-border bg-warning-subtle px-5 py-2 text-xs text-warning">
              Cowrie sessions could not be loaded. HTTP results remain available when present.
              <button type="button" onClick={() => void loadDirectory()} className="ml-2 font-semibold underline">Retry Cowrie</button>
            </p>
          )}
          {protocolFilter !== "ssh" && httpError && (
            <p role="alert" className="border-b border-warning-border bg-warning-subtle px-5 py-2 text-xs text-warning">
              HTTP sessions could not be refreshed. Cowrie sessions remain available.
            </p>
          )}
          {protocolFilter !== "ssh" && !httpItems && !httpError && sessionRows.length > 0 && (
            <p role="status" className="border-b border-border px-5 py-2 text-xs text-text-muted">Loading the recent HTTP event window…</p>
          )}
          {sessionRows.length > 0 ? (
            <DirectoryResults rows={sessionRows} />
          ) : shouldShowDirectorySkeleton ? (
            <DirectorySkeleton />
          ) : (protocolFilter !== "http" && isDirectoryUnavailable) || (protocolFilter !== "ssh" && httpError) ? (
            <div className="p-8 text-center">
              <RegionState kind="error" title="Session directory unavailable" description="The selected protocol data could not be retrieved." />
              {protocolFilter !== "http" && <button type="button" onClick={() => void loadDirectory()} className="ui-button mt-3 text-xs"><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Retry Cowrie</button>}
            </div>
          ) : (
            <div className="p-8">
              <RegionState
                kind="empty"
                title="No sessions found"
                description={queryInput ? "Try another IP, session ID, or request path." : "No sessions are available in the selected source window."}
              />
            </div>
          )}
        </div>

        {/* Cowrie history keeps its existing server-backed pagination in All and Cowrie views. */}
        {protocolFilter !== "http" && directoryTotal > 0 && directoryTotalPages > 1 && (
          <nav aria-label="Session directory pages" className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-surface-subtle/50 px-5 py-2.5 text-xs">
            <div className="flex items-center gap-3">
              <p className="text-text-muted">
                Cowrie page <strong className="text-text">{currentPage}</strong> of <strong className="text-text">{directoryTotalPages}</strong> ({directoryTotal.toLocaleString()} sessions)
                {protocolFilter === "all" && <span className="ml-1">· {matchingHttpCount} recent HTTP session{matchingHttpCount === 1 ? "" : "s"} included</span>}
              </p>
              {(directoryRefreshing || isPageChanging) && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-primary-border bg-primary-subtle px-2.5 py-0.5 font-mono text-[11px] font-semibold text-primary">
                  <RefreshCw className="h-3 w-3 animate-spin text-primary" aria-hidden="true" />
                  Loading page {currentPage}…
                </span>
              )}
              
              <div className="hidden sm:flex items-center gap-2 border-l border-border pl-4">
                <label htmlFor="rows-per-page" className="text-text-muted">Cowrie rows:</label>
                <select
                  id="rows-per-page"
                  value={pageSize}
                  disabled={directoryRefreshing || isPageChanging}
                  onChange={(e) => {
                    setIsPageChanging(true);
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
              <button
                type="button"
                disabled={currentPage === 1 || directoryRefreshing || isPageChanging}
                onClick={() => {
                  setIsPageChanging(true);
                  setCurrentPage(1);
                }}
                className="ui-button h-7 min-h-7 px-2 text-xs"
                aria-label="First page"
              >
                <ChevronsLeft className="h-3 w-3" aria-hidden="true" />
              </button>
              <button
                type="button"
                disabled={currentPage === 1 || directoryRefreshing || isPageChanging}
                onClick={() => {
                  setIsPageChanging(true);
                  setCurrentPage((page) => page - 1);
                }}
                className="ui-button h-7 min-h-7 px-2 text-xs"
                aria-label="Previous page"
              >
                <ChevronLeft className="h-3 w-3" aria-hidden="true" />
              </button>
              {getPageNumbers().map((pageNumber) => (
                <button
                  type="button"
                  key={pageNumber}
                  disabled={directoryRefreshing || isPageChanging}
                  onClick={() => {
                    setIsPageChanging(true);
                    setCurrentPage(pageNumber);
                  }}
                  aria-current={currentPage === pageNumber ? "page" : undefined}
                  className={cn(
                    "ui-button h-7 min-h-7 min-w-7 px-1.5 text-xs",
                    currentPage === pageNumber && "bg-primary text-surface font-semibold"
                  )}
                >
                  {pageNumber}
                </button>
              ))}
              <button
                type="button"
                disabled={currentPage === directoryTotalPages || directoryRefreshing || isPageChanging}
                onClick={() => {
                  setIsPageChanging(true);
                  setCurrentPage((page) => page + 1);
                }}
                className="ui-button h-7 min-h-7 px-2 text-xs"
                aria-label="Next page"
              >
                <ChevronRight className="h-3 w-3" aria-hidden="true" />
              </button>
              <button
                type="button"
                disabled={currentPage === directoryTotalPages || directoryRefreshing || isPageChanging}
                onClick={() => {
                  setIsPageChanging(true);
                  setCurrentPage(directoryTotalPages);
                }}
                className="ui-button h-7 min-h-7 px-2 text-xs"
                aria-label="Last page"
              >
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
          <div className="mt-1 space-y-1.5" aria-label={`Loading ${label}`}>
            <div className="ui-skeleton h-6 w-20 rounded-md" />
            <div className="ui-skeleton h-3 w-28 rounded-sm opacity-60" />
          </div>
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
    <>
      <div className="hidden divide-y divide-border md:block">
        {Array.from({ length: 5 }, (_, row) => (
          <div key={row} className="grid grid-cols-7 items-center gap-4 px-5 py-4">
            <div className="ui-skeleton h-4 w-28" />
            <div className="ui-skeleton h-5 w-24 rounded-md" />
            <div className="ui-skeleton h-4 w-28" />
            <div className="ui-skeleton h-4 w-24" />
            <div className="ui-skeleton h-4 w-28" />
            <div className="ui-skeleton ml-auto h-4 w-12" />
            <div className="ui-skeleton ml-auto h-6 w-16 rounded-md" />
          </div>
        ))}
      </div>
      <div className="grid gap-2 p-3 md:hidden">
        {Array.from({ length: 4 }, (_, row) => (
          <div key={row} className="rounded-lg border border-border p-3">
            <div className="ui-skeleton h-4 w-36" />
            <div className="mt-2 ui-skeleton h-3 w-28" />
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="ui-skeleton h-8 w-full" />
              <div className="ui-skeleton h-8 w-full" />
              <div className="ui-skeleton h-8 w-full" />
              <div className="ui-skeleton h-8 w-full" />
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function DirectoryResults({ rows }: { rows: SessionDirectoryRow[] }) {
  const router = useRouter();
  const openSession = (href: string) => router.push(href);

  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="ui-table min-w-[1080px] w-full text-xs">
          <thead>
            <tr className="border-b border-[#18227A]/15 bg-[#18227A]/[0.04] text-[#18227A] font-semibold">
              <th scope="col" className="py-3 px-5 text-left">Session</th>
              <th scope="col" className="py-3 px-5 text-left">Protocol / Sensor</th>
              <th scope="col" className="py-3 px-5 text-left">Origin</th>
              <th scope="col" className="py-3 px-5 text-left">Started</th>
              <th scope="col" className="py-3 px-5 text-left">Activity / attacker type</th>
              <th scope="col" className="py-3 px-5 text-right">Dwell time</th>
              <th scope="col" className="py-3 px-5 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/70">
            {rows.map((row) => {
              const ProtocolIcon = row.protocol === "HTTP" ? Globe : Terminal;
              return (
                <tr
                  key={row.key}
                  tabIndex={0}
                  aria-label={`Open ${row.protocol} session ${row.id}`}
                  onClick={() => openSession(row.href)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      openSession(row.href);
                    }
                  }}
                  className="group cursor-pointer transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary"
                >
                  <td className="max-w-[230px] py-3 px-5">
                    <Link href={row.href} onClick={(event) => event.stopPropagation()} title={row.id} className="font-mono font-semibold text-[#18227A] hover:text-primary">
                      {row.id.length > 18 ? `${row.id.slice(0, 14)}…${row.id.slice(-3)}` : row.id}
                    </Link>
                  </td>
                  <td className="py-3 px-5">
                    <span className={cn(
                      "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] font-bold uppercase tracking-wide",
                      row.protocol !== "HTTP"
                        ? "border-[#18227A]/20 bg-[#18227A]/[0.05] text-[#18227A]"
                        : "border-primary/25 bg-primary-subtle text-primary",
                    )}>
                      <ProtocolIcon className="h-3 w-3" aria-hidden="true" />
                      {row.protocol}
                    </span>
                    <span className="ml-2 text-text-muted">{row.sensor}</span>
                  </td>
                  <td className="py-3 px-5">
                    <div className="font-mono font-medium text-text">{row.origin}</div>
                    <div className="mt-0.5 text-[11px] text-text-muted">{row.originDetail}</div>
                  </td>
                  <td className="whitespace-nowrap py-3 px-5 text-text-muted" title={row.startedAt || undefined}>{row.startedLabel}</td>
                  <td className="py-3 px-5 text-text">
                    {row.protocol !== "HTTP"
                      ? <AttackerTypeBadge type={row.attackerType ?? "Unclassified"} />
                      : <>{row.activity}{row.activity.includes("injection hint") && <span className="ml-1 text-[10px] text-warning">· review only</span>}</>}
                  </td>
                  <td className="whitespace-nowrap py-3 px-5 text-right font-mono text-text-muted">{row.dwellTime}</td>
                  <td className="py-3 px-5 text-right">
                    <SessionStatusBadge status={row.status} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="grid gap-2 p-3 md:hidden">
        {rows.map((row) => {
          const ProtocolIcon = row.protocol === "HTTP" ? Globe : Terminal;
          return (
            <Link key={row.key} href={row.href} className="rounded-lg border border-border bg-surface p-3 transition hover:border-primary/40 hover:bg-surface-hover">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-mono text-xs font-semibold text-[#18227A]" title={row.id}>{row.id}</p>
                  <p className="mt-1 inline-flex items-center gap-1.5 text-[11px] text-text-muted">
                    <ProtocolIcon className="h-3 w-3 text-primary" aria-hidden="true" />
                    {row.protocol} <span aria-hidden="true">·</span> {row.sensor}
                  </p>
                </div>
                <SessionStatusBadge status={row.status} />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
                <div><span className="block text-[10px] uppercase tracking-wide text-text-subtle">Origin</span><span className="font-mono text-text">{row.origin}</span><span className="block text-[10px] text-text-muted">{row.originDetail}</span></div>
                <div><span className="block text-[10px] uppercase tracking-wide text-text-subtle">Started</span><span className="text-text">{row.startedLabel}</span></div>
                <div><span className="block text-[10px] uppercase tracking-wide text-text-subtle">{row.protocol !== "HTTP" ? "Attacker type" : "Activity"}</span>{row.protocol !== "HTTP" ? <AttackerTypeBadge type={row.attackerType ?? "Unclassified"} /> : <><span className="text-text">{row.activity}</span>{row.activity.includes("injection hint") && <span className="block text-[10px] text-warning">Review hint only</span>}</>}</div>
                <div><span className="block text-[10px] uppercase tracking-wide text-text-subtle">Dwell time</span><span className="font-mono text-text-muted">{row.dwellTime}</span></div>
              </div>
            </Link>
          );
        })}
      </div>
    </>
  );
}

function AttackerTypeBadge({ type }: { type: SessionAttackerType }) {
  const label = type === "ScriptKiddie" ? "Script Kiddie" : type;
  const color = type === "APT"
    ? "border-danger-border bg-danger-subtle text-danger"
    : type === "Bot"
      ? "border-border bg-surface-subtle text-text"
      : type === "ScriptKiddie"
        ? "border-warning-border bg-warning-subtle text-warning"
        : "border-border bg-surface-subtle text-text-muted";
  return <span className={cn("inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold", color)}>{label}</span>;
}

function SessionStatusBadge({ status }: { status: SessionDirectoryRow["status"] }) {
  const styles = status === "Active"
    ? "border-success-border bg-success-subtle text-success"
    : status === "Observed"
      ? "border-primary/20 bg-primary-subtle text-primary"
      : "border-border bg-surface-subtle text-text-muted";
  return <span className={cn("inline-flex whitespace-nowrap rounded-md border px-2 py-1 text-[10px] font-semibold", styles)}>{status}</span>;
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
