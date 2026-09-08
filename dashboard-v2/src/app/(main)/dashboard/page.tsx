"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ActivitySquare,
  AlertTriangle,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  Download,
  Globe,
  Maximize,
  Minimize,
  Radio,
  RefreshCw,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";

import RegionalMap from "@/components/dashboard/RegionalMap";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState, RefreshStatus, type RegionStatus } from "@/components/ui/RegionState";
import { SelectMenu } from "@/components/ui/SelectMenu";
import type {
  DashboardThreatEvent,
  ThreatDashboardSummary,
  ThreatDirectoryPage,
  ThreatSeverityFilter,
} from "@/lib/dashboardTypes";
import { classificationBadgeClass, severityDotClass, severityBarClass } from "@/lib/presentation";
import { cn } from "@/lib/utils";

const DIRECTORY_PAGE_SIZE = 20;
const severityOptions: ThreatSeverityFilter[] = ["All", "Critical", "High", "Medium", "Low"];

type RequestStatus = "loading" | "ready" | "error";

export default function DashboardPage() {
  const { threats: sessions, status, lastUpdated, refresh } = useThreatFeed();
  const mapPanel = useRef<HTMLDivElement>(null);
  const directoryRequest = useRef(0);
  const summaryRequest = useRef(0);
  const summaryRef = useRef<ThreatDashboardSummary | null>(null);
  const directoryRef = useRef<ThreatDirectoryPage | null>(null);
  const directoryLoaderRef = useRef<(background?: boolean) => Promise<void>>(async () => undefined);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [isHydrated, setIsHydrated] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [queryInput, setQueryInput] = useState("");
  const query = useDebouncedValue(queryInput, 320);
  const [severityFilter, setSeverityFilter] = useState<ThreatSeverityFilter>("All");
  const [filterOpen, setFilterOpen] = useState(false);
  const [summary, setSummary] = useState<ThreatDashboardSummary | null>(null);
  const [summaryStatus, setSummaryStatus] = useState<RequestStatus>("loading");
  const [directory, setDirectory] = useState<ThreatDirectoryPage | null>(null);
  const [directoryStatus, setDirectoryStatus] = useState<RequestStatus>("loading");
  const [directoryRefreshing, setDirectoryRefreshing] = useState(false);
  const [exportStatus, setExportStatus] = useState<string>("");
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setIsHydrated(true));
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const renderedSessions = useMemo(() => isHydrated ? sessions : [], [isHydrated, sessions]);
  const renderedStatus = isHydrated ? status : "loading";
  const renderedLastUpdated = isHydrated ? lastUpdated : null;
  const isInitialLoad = renderedStatus === "loading";
  const isUpdating = renderedStatus === "loading" || renderedStatus === "refreshing";
  const isRefreshDisabled = !isHydrated || isUpdating;
  const isUnavailable = renderedStatus === "error";
  const prioritySessions = useMemo(
    () => renderedSessions.filter((session) => session.severity === "Critical" || session.severity === "High").slice(0, 5),
    [renderedSessions],
  );

  useEffect(() => { summaryRef.current = summary; }, [summary]);
  useEffect(() => { directoryRef.current = directory; }, [directory]);

  const loadSummary = useCallback(async () => {
    const requestId = summaryRequest.current + 1;
    summaryRequest.current = requestId;
    if (!summaryRef.current) setSummaryStatus("loading");

    try {
      const response = await fetch("/api/threats/summary", { cache: "no-store" });
      if (!response.ok) throw new Error("Threat summary unavailable");
      const data: unknown = await response.json();
      if (!isThreatDashboardSummary(data) || summaryRequest.current !== requestId) return;
      setSummary(data);
      setSummaryStatus("ready");
    } catch {
      if (summaryRequest.current === requestId) setSummaryStatus("error");
    }
  }, []);

  const loadDirectory = useCallback(async (background = false) => {
    const requestId = directoryRequest.current + 1;
    directoryRequest.current = requestId;
    if (background || directoryRef.current) setDirectoryRefreshing(true);
    else setDirectoryStatus("loading");

    try {
      const params = new URLSearchParams({ page: String(currentPage), pageSize: String(DIRECTORY_PAGE_SIZE) });
      if (query) params.set("query", query);
      if (severityFilter !== "All") params.set("severity", severityFilter);
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
  }, [currentPage, query, severityFilter]);

  useEffect(() => { directoryLoaderRef.current = loadDirectory; }, [loadDirectory]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadSummary(), 0);
    return () => window.clearTimeout(timer);
  }, [loadSummary]);
  useEffect(() => {
    const timer = window.setTimeout(() => void loadDirectory(), 0);
    return () => window.clearTimeout(timer);
  }, [loadDirectory]);

  useEffect(() => {
    if (!lastUpdated) return;
    const timer = window.setTimeout(() => {
      void loadSummary();
      void directoryLoaderRef.current(true);
    }, 800);
    return () => window.clearTimeout(timer);
  }, [lastUpdated, loadSummary]);

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
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, [isFullScreen]);

  const feedState = statePresentation(renderedStatus);
  const directoryItems = directory?.items ?? [];
  const directoryTotal = directory?.total ?? 0;
  const directoryTotalPages = directory?.totalPages ?? 1;
  const isDirectoryInitialLoad = directoryStatus === "loading" && !directory;
  const isDirectoryUnavailable = directoryStatus === "error" && !directory;
  const hasDirectoryRefreshError = directoryStatus === "error" && Boolean(directory);
  const metrics = [
    { title: "Sessions observed", value: summary?.sessions, description: "Last 24 hours", icon: ActivitySquare, tone: "info" as const },
    { title: "Distinct sources", value: summary?.uniqueSources, description: "Unique origin IPs · 24 hours", icon: Globe, tone: "info" as const },
    { title: "High / Critical", value: summary?.prioritySessions, description: "Needs priority review · 24 hours", icon: AlertTriangle, tone: "danger" as const },
    { title: "Live feed", value: feedState.metric, description: formatUpdatedAt(renderedLastUpdated), icon: Radio, tone: feedState.tone },
  ];

  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    const end = Math.min(directoryTotalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
  };

  const handleExport = async () => {
    if (!directoryTotal || isExporting) return;
    setIsExporting(true);
    setExportStatus("Preparing server-side export…");
    try {
      const params = new URLSearchParams();
      if (query) params.set("query", query);
      if (severityFilter !== "All") params.set("severity", severityFilter);
      const response = await fetch(`/api/threats/directory/export?${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error("Threat directory export unavailable");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `pti-incursion-directory-${new Date().toISOString().slice(0, 10)}.csv`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      const exported = Number.parseInt(response.headers.get("X-PTI-Export-Count") ?? "0", 10);
      const total = Number.parseInt(response.headers.get("X-PTI-Export-Total") ?? "0", 10);
      const truncated = response.headers.get("X-PTI-Export-Truncated") === "true";
      setExportStatus(truncated ? `Downloaded ${exported.toLocaleString()} of ${total.toLocaleString()} matching sessions.` : `Downloaded ${exported.toLocaleString()} matching session${exported === 1 ? "" : "s"}.`);
    } catch {
      setExportStatus("Export unavailable. Please try again.");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-7 pb-10">
      <header className="flex flex-col justify-between gap-5 border-b border-border pb-6 xl:flex-row xl:items-end">
        <div>
          <div className="flex flex-wrap items-center gap-3 text-xs font-semibold uppercase tracking-[0.14em] text-info"><span>Operations / Monitoring</span><span className="h-1 w-1 rounded-full bg-border-strong" aria-hidden="true" /><span className="flex items-center gap-2 text-text-subtle"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Live workspace</span></div>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight sm:text-[28px] sm:leading-9">Overview Dashboard</h1>
          <p className="mt-2 max-w-2xl text-sm text-text-muted sm:text-base">Prioritize fresh signals, then move into the full investigation directory.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 xl:justify-end">
          <span role="status" aria-live="polite" className={cn("ui-badge", feedState.className)}>{renderedStatus === "refreshing" ? <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> : <Radio className="h-3.5 w-3.5" aria-hidden="true" />}{feedState.label}</span>
          <RefreshStatus status={renderedStatus} />
          <button type="button" onClick={() => { void refresh(); void loadSummary(); void loadDirectory(true); }} disabled={isRefreshDisabled} className="ui-button min-h-9 px-3 text-xs" aria-label="Refresh dashboard data"><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Refresh</button>
        </div>
      </header>

      <section aria-label="Overview metrics" aria-busy={summaryStatus === "loading" || isUpdating} className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(({ title, value, description, icon: Icon, tone }, index) => (
          <article key={title} className={cn("ui-panel ui-panel-interactive relative overflow-hidden p-5 sm:p-6", index === 0 && "border-t-2 border-t-info")}>
            <div className="flex items-start justify-between gap-4"><div className="min-w-0"><p className="text-sm font-medium text-text-muted">{title}</p>
              {summaryStatus === "loading" && index < 3 ? <div className="mt-4 space-y-2" aria-label={`Loading ${title}`}><div className="ui-skeleton h-8 w-20" /><div className="ui-skeleton h-3 w-32" /></div>
                : summaryStatus === "error" && !summary && index < 3 ? <div className="mt-4"><p className="flex items-center gap-2 text-sm font-medium text-danger"><AlertTriangle className="h-4 w-4" aria-hidden="true" />Unavailable</p><button type="button" onClick={() => void loadSummary()} className="mt-2 text-xs font-medium text-primary hover:text-primary-action-hover">Retry summary</button></div>
                  : <><p className={cn("mt-3 text-[28px] font-semibold leading-9 tabular-nums", tone === "danger" && typeof value === "number" && value > 0 ? "text-danger" : "text-text")}>{value ?? "—"}</p><p className="mt-2 min-h-5 text-xs text-text-muted">{description}</p></>}
            </div><span className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-lg border", tone === "danger" ? "border-danger-border bg-danger-subtle text-danger" : tone === "success" ? "border-success-border bg-success-subtle text-success" : tone === "warning" ? "border-warning-border bg-warning-subtle text-warning" : tone === "info" ? "border-info-border bg-info-subtle text-info" : "border-primary-border bg-primary-subtle text-primary")}><Icon className="h-[18px] w-[18px]" aria-hidden="true" /></span></div>
          </article>
        ))}
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:gap-6" aria-label="Operational monitoring">
        <div ref={mapPanel} role={isFullScreen ? "dialog" : undefined} aria-modal={isFullScreen ? true : undefined} aria-labelledby="distribution-title" className={cn("ui-panel flex min-h-[470px] flex-col overflow-hidden", isFullScreen ? "fixed inset-0 z-[100] h-dvh w-screen rounded-none" : "xl:col-span-8")}>
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border bg-surface px-5 py-4 sm:px-6"><div><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-info"><Globe className="h-4 w-4" aria-hidden="true" />Attack surface</div><h2 id="distribution-title" className="mt-1 text-base font-semibold sm:text-lg">Global Attack Distribution</h2><p className="mt-1 text-sm text-text-muted">Explore the geographic origin of observed sessions.</p></div><div className="flex flex-wrap items-center gap-3 text-xs text-text-muted"><span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rotate-45 bg-danger" aria-hidden="true" />Critical</span><span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-info" aria-hidden="true" />Active</span><span className="flex items-center gap-2"><span className="h-2.5 w-2.5 border border-neutral" aria-hidden="true" />Dormant</span><button onClick={() => setIsFullScreen((value) => !value)} className="ui-button h-9 min-h-9 w-9 p-0" title={isFullScreen ? "Exit full screen" : "Open full screen"} aria-label={isFullScreen ? "Exit full screen" : "Open full screen"}>{isFullScreen ? <Minimize className="h-4 w-4" aria-hidden="true" /> : <Maximize className="h-4 w-4" aria-hidden="true" />}</button></div></div>
          <div className="min-h-0 flex-1 bg-surface-subtle"><RegionalMap /></div>
        </div>

        <aside className="ui-panel flex min-h-[470px] flex-col overflow-hidden xl:col-span-4" aria-labelledby="priority-title" aria-busy={isUpdating}>
          <div className="flex items-start justify-between gap-4 border-b border-border bg-surface px-5 py-4 sm:px-6"><div><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-danger"><AlertTriangle className="h-4 w-4" aria-hidden="true" />Priority queue</div><h2 id="priority-title" className="mt-1 text-base font-semibold sm:text-lg">High-risk sessions</h2><p className="mt-1 text-sm text-text-muted">Critical and High signals from the live feed.</p></div><span className={cn("mt-1 flex h-2.5 w-2.5 shrink-0 rounded-full", renderedStatus === "error" ? "bg-danger" : renderedStatus === "stale" ? "bg-warning" : renderedStatus === "ready" ? "bg-success" : "bg-info")} title={feedState.label} aria-label={feedState.label} /></div>
          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-3">{isInitialLoad && Array.from({ length: 5 }, (_, index) => <PrioritySkeleton key={`priority-loading-${index}`} />)}{!isInitialLoad && isUnavailable && <RegionState kind="error" title="Priority queue unavailable" description="The live session feed could not be loaded." />}{!isInitialLoad && !isUnavailable && prioritySessions.length === 0 && <RegionState kind="empty" title="No priority sessions" description="The latest response contains no Critical or High sessions." />}{!isInitialLoad && !isUnavailable && prioritySessions.map((session) => <PrioritySession key={session.id} session={session} />)}</div>
          <div className="border-t border-border bg-surface-subtle p-3"><Link href="/threat-intel" className="ui-button w-full justify-between border-primary-border bg-primary-subtle text-primary hover:bg-primary-border/20">Open threat intelligence<ArrowUpRight className="h-4 w-4" aria-hidden="true" /></Link></div>
        </aside>
      </section>

      <section className="ui-panel overflow-hidden" aria-labelledby="directory-title" aria-busy={isDirectoryInitialLoad || directoryRefreshing}>
        <div className="border-b border-border bg-surface px-5 py-5 sm:px-6"><div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between"><div><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-info"><ActivitySquare className="h-4 w-4" aria-hidden="true" />Investigation directory</div><h2 id="directory-title" className="mt-1 text-base font-semibold sm:text-lg">Live Incursion Directory</h2><p className="mt-1 text-sm text-text-muted">Search the full session directory, not only the live map buffer.</p></div><div className="flex flex-col gap-3 sm:flex-row sm:items-center"><label className="relative block min-w-0 sm:w-64"><span className="sr-only">Search incursion directory</span><Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-subtle" aria-hidden="true" /><input value={queryInput} onChange={(event) => { setQueryInput(event.target.value); setCurrentPage(1); }} type="search" placeholder="Session, IP, sensor…" className="ui-field pl-10 pr-8" />{queryInput && <button type="button" onClick={() => { setQueryInput(""); setCurrentPage(1); }} className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-text-subtle hover:text-text" aria-label="Clear search input"><X className="h-3.5 w-3.5" aria-hidden="true" /></button>}</label><button onClick={() => setFilterOpen((value) => !value)} className={cn("ui-button", (filterOpen || severityFilter !== "All") && "border-primary bg-primary-subtle text-primary")} aria-expanded={filterOpen} aria-controls="incursion-filter-panel"><SlidersHorizontal className="h-4 w-4" aria-hidden="true" />Filter{severityFilter !== "All" && <span className="grid h-5 min-w-5 place-items-center rounded-full bg-primary px-1 text-xs text-on-primary">1</span>}</button><button onClick={() => void handleExport()} disabled={!directoryTotal || isExporting} className="ui-button"><Download className="h-4 w-4" aria-hidden="true" />{isExporting ? "Exporting…" : "Export"}</button></div></div>
          {filterOpen && <div id="incursion-filter-panel" className="mt-4 flex flex-col gap-3 rounded-lg border border-border bg-surface-subtle p-3 sm:flex-row sm:items-center sm:justify-between"><div className="flex items-center gap-3 text-sm font-medium text-text-muted"><span>Severity</span><SelectMenu value={severityFilter} onValueChange={(value) => { setSeverityFilter(value as ThreatSeverityFilter); setCurrentPage(1); }} options={severityOptions} className="min-w-32" /></div><div className="flex items-center justify-between gap-3 text-xs text-text-muted sm:justify-end"><span>{directoryTotal.toLocaleString()} matching session{directoryTotal === 1 ? "" : "s"}</span>{(queryInput || severityFilter !== "All") && <button onClick={() => { setQueryInput(""); setSeverityFilter("All"); setCurrentPage(1); }} className="inline-flex items-center gap-1.5 font-medium text-primary hover:text-primary-action-hover"><X className="h-3.5 w-3.5" aria-hidden="true" />Clear filters</button>}</div></div>}
          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted" aria-live="polite">{directoryRefreshing && <span className="inline-flex items-center gap-1.5"><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Updating directory…</span>}{hasDirectoryRefreshError && <span className="inline-flex items-center gap-1.5 text-warning"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />Refresh failed · showing the last successful result</span>}{exportStatus && <span>{exportStatus}</span>}</div>
        </div>
        <div className="min-h-[360px]">{isDirectoryInitialLoad && <DirectorySkeleton />}{isDirectoryUnavailable && <div className="p-4 sm:p-6"><RegionState kind="error" title="Sessions unavailable" description="We couldn’t load the session directory." /><button type="button" onClick={() => void loadDirectory()} className="ui-button mt-4"><RefreshCw className="h-4 w-4" aria-hidden="true" />Retry directory</button></div>}{!isDirectoryInitialLoad && !isDirectoryUnavailable && directoryItems.length === 0 && <div className="p-4 sm:p-6"><RegionState kind="empty" title={directoryTotal === 0 && (queryInput || severityFilter !== "All") ? "No matching sessions" : "No active sessions"} description={directoryTotal === 0 && (queryInput || severityFilter !== "All") ? "Try a different search or severity filter." : "No sessions were returned from the directory."} /></div>}{!isDirectoryInitialLoad && !isDirectoryUnavailable && directoryItems.length > 0 && <DirectoryResults sessions={directoryItems} />}</div>
        {directoryTotal > 0 && directoryTotalPages > 1 && <nav aria-label="Directory pages" className="flex flex-wrap items-center gap-2 border-t border-border bg-surface-subtle p-4"><p className="mr-auto text-xs text-text-muted">Page {currentPage} of {directoryTotalPages} · {directoryTotal.toLocaleString()} sessions</p><button disabled={currentPage === 1} onClick={() => setCurrentPage((page) => page - 1)} className="ui-button min-h-9 px-3 text-xs"><ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />Prev</button>{getPageNumbers().map((pageNumber) => <button key={pageNumber} onClick={() => setCurrentPage(pageNumber)} aria-current={currentPage === pageNumber ? "page" : undefined} aria-label={`Page ${pageNumber}`} className="ui-button min-h-9 min-w-9 px-2 text-xs">{pageNumber}</button>)}<button disabled={currentPage === directoryTotalPages} onClick={() => setCurrentPage((page) => page + 1)} className="ui-button min-h-9 px-3 text-xs">Next<ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></button></nav>}
      </section>
    </div>
  );
}

function PrioritySkeleton() { return <div className="flex gap-3 rounded-lg border border-border p-3" aria-hidden="true"><div className="ui-skeleton h-8 w-1 shrink-0" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-3 w-20" /><div className="ui-skeleton h-4 w-4/5" /><div className="ui-skeleton h-3 w-2/5" /></div></div>; }

function PrioritySession({ session }: { session: DashboardThreatEvent }) { return <Link href={`/threat-intel/${session.id}`} className="group flex gap-3 rounded-lg border border-transparent p-3 hover:border-primary-border hover:bg-primary-subtle focus-visible:border-primary-border"><span className={cn("mt-1 h-9 w-1 shrink-0 rounded-full", severityBarClass(session.severity))} aria-hidden="true" /><span className="min-w-0 flex-1"><span className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-xs text-text-subtle">{session.time}</span><SeverityBadge severity={session.severity} className="px-2 py-1 text-xs" /></span><span className="mt-2 flex min-w-0 items-center gap-1.5 text-sm"><span className="truncate font-medium text-text">{session.classification}</span><span className="text-text-subtle">from</span><span className="truncate font-mono text-xs text-primary">{session.sourceIp}</span></span><span className="mt-1 block truncate text-xs text-text-muted">{session.sensor}</span></span><ArrowUpRight className="mt-1 h-4 w-4 shrink-0 text-text-subtle transition-colors group-hover:text-primary" aria-hidden="true" /></Link>; }

function DirectorySkeleton() { return <div className="space-y-px bg-border" aria-label="Loading session directory">{Array.from({ length: 6 }, (_, row) => <div key={row} className="grid min-h-[68px] grid-cols-4 gap-4 bg-surface p-4 sm:grid-cols-7 sm:px-6">{Array.from({ length: 7 }, (_, column) => <div key={column} className={cn("ui-skeleton h-4", column > 3 ? "hidden sm:block" : "")} />)}</div>)}</div>; }

function DirectoryResults({ sessions }: { sessions: DashboardThreatEvent[] }) { return <><div className="space-y-3 p-3 md:hidden">{sessions.map((session) => <article key={session.id} className="rounded-lg border border-border bg-surface p-4 shadow-[var(--shadow-card)]"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="flex items-center gap-2 font-mono text-sm font-medium text-text"><span className={cn("h-2 w-2 shrink-0 rounded-full", severityDotClass(session.severity))} aria-hidden="true" />{session.id}</p><p className="mt-1 font-mono text-xs text-primary">{session.sourceIp}</p></div><SeverityBadge severity={session.severity} /></div><dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 text-xs"><div><dt className="text-text-subtle">Attacker type</dt><dd className="mt-1"><span className={cn("ui-badge", classificationBadgeClass(session.classification, session.typeColor))}>{session.classification}</span></dd></div><div><dt className="text-text-subtle">Session status</dt><dd className="mt-1 font-mono text-text">{session.duration}</dd></div><div><dt className="text-text-subtle">Observed</dt><dd className="mt-1 font-mono text-text">{session.date} {session.time}</dd></div><div><dt className="text-text-subtle">Sensor</dt><dd className="mt-1 truncate text-text" title={session.sensor}>{session.sensor}</dd></div></dl><Link href={`/threat-intel/${session.id}`} className="ui-button mt-4 w-full text-primary">View details<ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" /></Link></article>)}</div><div className="hidden h-[390px] md:block"><div className="ui-scroll-region h-full" role="region" aria-label="Incursion directory table. Scroll to view all rows and columns." tabIndex={0}><table className="ui-table min-w-[980px]"><thead><tr>{["SESSION ID", "ORIGIN IP", "ATTACKER TYPE", "SEVERITY", "DATE & TIME", "SESSION STATUS", "ACTION"].map((label) => <th key={label} scope="col" className={label === "ACTION" ? "text-right" : undefined}>{label}</th>)}</tr></thead><tbody>{sessions.map((session) => <tr key={session.id} className="group text-text-muted"><td><span className="inline-flex items-center gap-2" title={session.id} aria-label={session.id} tabIndex={0}><span className={cn("h-2 w-2 shrink-0 rounded-full", severityDotClass(session.severity))} aria-hidden="true" /><span className="font-mono text-sm font-medium text-text">{session.id.length > 12 ? `${session.id.substring(0, 10).toUpperCase()}…` : session.id.toUpperCase()}</span></span></td><td className="font-mono text-sm text-text">{session.sourceIp}</td><td><span className={cn("ui-badge", classificationBadgeClass(session.classification, session.typeColor))}>{session.classification}</span></td><td><SeverityBadge severity={session.severity} /></td><td className="font-mono text-xs"><div className="text-text">{session.date}</div><div className="mt-1 text-text-subtle">{session.time}</div></td><td className="font-mono text-xs">{session.duration}</td><td className="text-right"><Link href={`/threat-intel/${session.id}`} className="ui-button min-h-9 px-3 text-xs text-primary">View Details<ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" /></Link></td></tr>)}</tbody></table></div></div></>; }
function statePresentation(status: RegionStatus) { if (status === "error") return { label: "Feed unavailable", metric: "Offline", tone: "danger" as const, className: "border-danger-border bg-danger-subtle text-danger" }; if (status === "stale") return { label: "Feed stale", metric: "Stale", tone: "warning" as const, className: "border-warning-border bg-warning-subtle text-warning" }; if (status === "refreshing") return { label: "Refreshing feed", metric: "Updating", tone: "info" as const, className: "border-info-border bg-info-subtle text-info" }; if (status === "loading") return { label: "Connecting to feed", metric: "Connecting", tone: "info" as const, className: "border-info-border bg-info-subtle text-info" }; return { label: "Live feed active", metric: "Connected", tone: "success" as const, className: "border-success-border bg-success-subtle text-success" }; }
function formatUpdatedAt(timestamp: number | null) { return timestamp ? `Updated ${new Date(timestamp).toLocaleTimeString([], { hour12: false })}` : "Awaiting first response"; }
function useDebouncedValue(value: string, delay: number) { const [debouncedValue, setDebouncedValue] = useState(value); useEffect(() => { const timer = window.setTimeout(() => setDebouncedValue(value), delay); return () => window.clearTimeout(timer); }, [delay, value]); return debouncedValue; }
function isThreatDashboardSummary(value: unknown): value is ThreatDashboardSummary { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const summary = value as Record<string, unknown>; return typeof summary.windowHours === "number" && typeof summary.sessions === "number" && typeof summary.uniqueSources === "number" && typeof summary.prioritySessions === "number"; }
function isThreatDirectoryPage(value: unknown): value is ThreatDirectoryPage { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const page = value as Record<string, unknown>; return Array.isArray(page.items) && typeof page.page === "number" && typeof page.pageSize === "number" && typeof page.total === "number" && typeof page.totalPages === "number"; }
