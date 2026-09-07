"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  Activity,
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
import { RegionState, RefreshStatus } from "@/components/ui/RegionState";
import { SelectMenu } from "@/components/ui/SelectMenu";
import { classificationBadgeClass } from "@/lib/presentation";
import { cn } from "@/lib/utils";

type SeverityFilter = "All" | "Critical" | "High" | "Medium" | "Low";

const ITEMS_PER_PAGE = 10;
const severityOptions: SeverityFilter[] = ["All", "Critical", "High", "Medium", "Low"];

export default function DashboardPage() {
  const { threats: sessions, status, lastUpdated, refresh } = useThreatFeed();
  const mapPanel = useRef<HTMLDivElement>(null);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [isHydrated, setIsHydrated] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("All");
  const [filterOpen, setFilterOpen] = useState(false);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setIsHydrated(true));
    return () => window.cancelAnimationFrame(frame);
  }, []);
  const renderedSessions = useMemo(() => isHydrated ? sessions : [], [isHydrated, sessions]);
  const renderedStatus = isHydrated ? status : "loading";
  const renderedLastUpdated = isHydrated ? lastUpdated : null;
  const stats = useMemo(() => {
    const critical = renderedSessions.filter((event) => event.severity === "Critical" || event.severity === "High").length;
    const total = renderedSessions.length.toString();
    return { total, active: total, critical, health: "99.9%" };
  }, [renderedSessions]);

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
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, [isFullScreen]);

  const filteredSessions = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    return renderedSessions.filter((session) => {
      const matchesSeverity = severityFilter === "All" || session.severity === severityFilter;
      if (!matchesSeverity) return false;
      if (!normalizedQuery) return true;

      return [session.id, session.sourceIp, session.sensor, session.classification, session.severity]
        .some((value) => value.toLowerCase().includes(normalizedQuery));
    });
  }, [query, renderedSessions, severityFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredSessions.length / ITEMS_PER_PAGE));
  const displayPage = Math.min(currentPage, totalPages);
  const currentData = filteredSessions.slice((displayPage - 1) * ITEMS_PER_PAGE, displayPage * ITEMS_PER_PAGE);
  const isInitialLoad = renderedStatus === "loading";
  const isUpdating = renderedStatus === "loading" || renderedStatus === "refreshing";
  const isRefreshDisabled = !isHydrated || isUpdating;
  const isUnavailable = renderedStatus === "error";
  const feedState = renderedStatus === "error"
    ? { label: "Feed unavailable", className: "border-danger-border bg-danger-subtle text-danger" }
    : renderedStatus === "stale"
      ? { label: "Feed stale", className: "border-warning-border bg-warning-subtle text-warning" }
      : renderedStatus === "refreshing"
        ? { label: "Refreshing feed", className: "border-info-border bg-info-subtle text-info" }
        : renderedStatus === "loading"
          ? { label: "Connecting to feed", className: "border-info-border bg-info-subtle text-info" }
          : { label: "Live feed active", className: "border-success-border bg-success-subtle text-success" };

  const getPageNumbers = () => {
    let start = Math.max(1, displayPage - 2);
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
  };

  const handleExport = () => {
    if (!filteredSessions.length) return;

    const escapeCsv = (value: string) => `"${value.replace(/"/g, '""')}"`;
    const rows = [
      ["Session ID", "Origin IP", "Attacker Type", "Date & Time", "Duration"],
      ...filteredSessions.map((session) => [
        session.id,
        session.sourceIp,
        session.classification,
        `${session.date} ${session.time}`,
        session.duration,
      ]),
    ];
    const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `pti-incursion-directory-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const metrics = [
    { title: "Total sessions", value: stats.total, icon: ActivitySquare, tone: "primary" as const },
    { title: "Active incursions", value: stats.active, icon: AlertTriangle, tone: "danger" as const },
    { title: "Honeypot health", value: stats.health, icon: Activity, tone: "primary" as const },
  ];

  return (
    <div className="space-y-7 pb-10">
      <header className="flex flex-col justify-between gap-5 border-b border-border pb-6 xl:flex-row xl:items-end">
        <div>
          <div className="flex flex-wrap items-center gap-3 text-xs font-semibold uppercase tracking-[0.14em] text-primary">
            <span>Operations / Monitoring</span>
            <span className="h-1 w-1 rounded-full bg-border-strong" aria-hidden="true" />
            <span className="flex items-center gap-2 text-text-subtle">
              <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
              Live workspace
            </span>
          </div>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight sm:text-[28px] sm:leading-9">Overview Dashboard</h1>
          <p className="mt-2 max-w-2xl text-sm text-text-muted sm:text-base">Real-time session monitoring and threat directory.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 xl:justify-end">
          <span role="status" aria-live="polite" className={cn("ui-badge", feedState.className)}>
            {renderedStatus === "refreshing" ? <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> : <Radio className="h-3.5 w-3.5" aria-hidden="true" />}
            {feedState.label}
          </span>
          <span className="font-mono text-xs text-text-subtle">{formatUpdatedAt(renderedLastUpdated)}</span>
          <RefreshStatus status={renderedStatus} />
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={isRefreshDisabled}
            className="ui-button min-h-9 px-3 text-xs"
            aria-label="Refresh dashboard data"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Refresh
          </button>
        </div>
      </header>

      <section aria-label="Overview metrics" aria-busy={isUpdating} className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {metrics.map(({ title, value, icon: Icon, tone }, index) => (
          <article key={title} className={cn("ui-panel ui-panel-interactive relative overflow-hidden p-5 sm:p-6", index === 0 && "border-t-2 border-t-primary")}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm font-medium text-text-muted">{title}</p>
                {isInitialLoad ? (
                  <div className="mt-4 space-y-2" aria-label={`Loading ${title}`}>
                    <div className="ui-skeleton h-8 w-24" />
                    <div className="ui-skeleton h-3 w-36" />
                  </div>
                ) : isUnavailable ? (
                  <p className="mt-5 flex items-center gap-2 text-sm font-medium text-danger">
                    <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                    Unavailable · request failed
                  </p>
                ) : (
                  <div className="mt-3 flex flex-wrap items-baseline gap-2">
                    <span className="text-[28px] font-semibold leading-9 tabular-nums text-text">{value}</span>
                    {index === 2 && <span className="text-sm text-text-muted">Uptime</span>}
                  </div>
                )}
              </div>
              <span className={cn(
                "grid h-10 w-10 shrink-0 place-items-center rounded-lg border",
                tone === "danger" ? "border-danger-border bg-danger-subtle text-danger" : "border-primary-border bg-primary-subtle text-primary",
              )}>
                <Icon className="h-[18px] w-[18px]" aria-hidden="true" />
              </span>
            </div>
            {!isInitialLoad && !isUnavailable && index === 1 && (
              <p className="mt-4 flex items-center gap-2 text-sm text-danger">
                <span className="h-2 w-2 rounded-sm bg-danger" aria-hidden="true" />
                {stats.critical} Critical Severity
              </p>
            )}
            {!isInitialLoad && !isUnavailable && index === 2 && (
              <div className="mt-4 h-2 overflow-hidden rounded-full bg-surface-subtle" aria-label={`${stats.health} uptime`} role="img">
                <div className="h-full rounded-full bg-primary transition-[width] duration-150" style={{ width: stats.health }} />
              </div>
            )}
          </article>
        ))}
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:gap-6" aria-label="Operational monitoring">
        <div
          ref={mapPanel}
          role={isFullScreen ? "dialog" : undefined}
          aria-modal={isFullScreen ? true : undefined}
          aria-labelledby="distribution-title"
          className={cn(
            "ui-panel flex min-h-[470px] flex-col overflow-hidden",
            isFullScreen ? "fixed inset-0 z-[100] h-dvh w-screen rounded-none" : "xl:col-span-8",
          )}
        >
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <Globe className="h-4 w-4" aria-hidden="true" />
                Attack surface
              </div>
              <h2 id="distribution-title" className="mt-1 text-base font-semibold sm:text-lg">Global Attack Distribution</h2>
              <p className="mt-1 text-sm text-text-muted">Explore the geographic origin of observed sessions.</p>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-text-muted">
              <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rotate-45 bg-danger" aria-hidden="true" />Critical</span>
              <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full bg-info" aria-hidden="true" />Active</span>
              <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 border border-neutral" aria-hidden="true" />Dormant</span>
              <button
                onClick={() => setIsFullScreen((value) => !value)}
                className="ui-button h-9 min-h-9 w-9 p-0"
                title={isFullScreen ? "Exit full screen" : "Open full screen"}
                aria-label={isFullScreen ? "Exit full screen" : "Open full screen"}
              >
                {isFullScreen ? <Minimize className="h-4 w-4" aria-hidden="true" /> : <Maximize className="h-4 w-4" aria-hidden="true" />}
              </button>
            </div>
          </div>
          <div className="min-h-0 flex-1 bg-surface-subtle"><RegionalMap /></div>
        </div>

        <aside className="ui-panel flex min-h-[470px] flex-col overflow-hidden xl:col-span-4" aria-labelledby="signals-title" aria-busy={isUpdating}>
          <div className="flex items-start justify-between gap-4 border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <Activity className="h-4 w-4" aria-hidden="true" />
                Live signal
              </div>
              <h2 id="signals-title" className="mt-1 text-base font-semibold sm:text-lg">Recent sessions</h2>
              <p className="mt-1 text-sm text-text-muted">Latest records from the session directory.</p>
            </div>
            <span
              className={cn(
                "mt-1 flex h-2.5 w-2.5 shrink-0 rounded-full",
                renderedStatus === "error" ? "bg-danger" : renderedStatus === "stale" ? "bg-warning" : renderedStatus === "ready" ? "bg-success" : "bg-info",
              )}
              title={renderedStatus === "error" ? "Feed unavailable" : renderedStatus === "stale" ? "Feed stale" : renderedStatus === "ready" ? "Feed active" : "Feed connecting"}
              aria-label={renderedStatus === "error" ? "Feed unavailable" : renderedStatus === "stale" ? "Feed stale" : renderedStatus === "ready" ? "Feed active" : "Feed connecting"}
            />
          </div>

          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-3">
            {isInitialLoad && Array.from({ length: 5 }, (_, index) => (
              <div key={`signal-loading-${index}`} className="flex gap-3 rounded-lg border border-border p-3" aria-hidden="true">
                <div className="ui-skeleton h-8 w-1 shrink-0" />
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="ui-skeleton h-3 w-20" />
                  <div className="ui-skeleton h-4 w-4/5" />
                  <div className="ui-skeleton h-3 w-2/5" />
                </div>
              </div>
            ))}
            {!isInitialLoad && isUnavailable && <RegionState kind="error" title="Signals unavailable" description="The latest session directory could not be loaded." />}
            {!isInitialLoad && !isUnavailable && renderedSessions.length === 0 && <RegionState kind="empty" title="No recent sessions" description="No sessions were returned in the last successful response." />}
            {!isInitialLoad && !isUnavailable && renderedSessions.slice(0, 5).map((session) => (
              <Link
                key={session.id}
                href={`/threat-intel/${session.id}`}
                className="group flex gap-3 rounded-lg border border-transparent p-3 hover:border-primary-border hover:bg-primary-subtle focus-visible:border-primary-border"
              >
                <span className={cn("mt-1 h-9 w-1 shrink-0 rounded-full", severityBarClass(session.severity))} aria-hidden="true" />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs text-text-subtle">{session.time}</span>
                    <SeverityBadge severity={session.severity} className="px-2 py-1 text-xs" />
                  </span>
                  <span className="mt-2 flex min-w-0 items-center gap-1.5 text-sm">
                    <span className="truncate font-medium text-text">{session.classification}</span>
                    <span className="text-text-subtle">from</span>
                    <span className="truncate font-mono text-xs text-primary">{session.sourceIp}</span>
                  </span>
                  <span className="mt-1 block truncate text-xs text-text-muted">{session.sensor}</span>
                </span>
                <ArrowUpRight className="mt-1 h-4 w-4 shrink-0 text-text-subtle transition-colors group-hover:text-primary" aria-hidden="true" />
              </Link>
            ))}
          </div>

          <div className="border-t border-border bg-surface-subtle p-3">
            <Link href="/threat-intel" className="ui-button w-full justify-between border-primary-border bg-primary-subtle text-primary hover:bg-primary-border/20">
              Open threat intelligence
              <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
        </aside>
      </section>

      <section className="ui-panel overflow-hidden" aria-labelledby="directory-title" aria-busy={isUpdating}>
        <div className="border-b border-border bg-surface px-5 py-5 sm:px-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <ActivitySquare className="h-4 w-4" aria-hidden="true" />
                Investigation queue
              </div>
              <h2 id="directory-title" className="mt-1 text-base font-semibold sm:text-lg">Live Incursion Directory</h2>
              <p className="mt-1 text-sm text-text-muted">Review the latest sessions and open a detailed threat profile.</p>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <label className="relative block min-w-0 sm:w-64">
                <span className="sr-only">Search incursion directory</span>
                <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-text-subtle" aria-hidden="true" />
                <input
                  value={query}
                  onChange={(event) => { setQuery(event.target.value); setCurrentPage(1); }}
                  type="search"
                  placeholder="Search sessions..."
                  className="ui-field pl-10"
                />
              </label>
              <button
                onClick={() => setFilterOpen((value) => !value)}
                className={cn("ui-button", (filterOpen || severityFilter !== "All") && "border-primary bg-primary-subtle text-primary")}
                aria-expanded={filterOpen}
                aria-controls="incursion-filter-panel"
              >
                <SlidersHorizontal className="h-4 w-4" aria-hidden="true" />
                Filter
                {severityFilter !== "All" && <span className="grid h-5 min-w-5 place-items-center rounded-full bg-primary px-1 text-xs text-on-primary">1</span>}
              </button>
              <button onClick={handleExport} disabled={!filteredSessions.length} className="ui-button">
                <Download className="h-4 w-4" aria-hidden="true" />
                Export
              </button>
            </div>
          </div>

          {filterOpen && (
            <div id="incursion-filter-panel" className="mt-4 flex flex-col gap-3 rounded-lg border border-border bg-surface-subtle p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3 text-sm font-medium text-text-muted">
                <span>Severity</span>
                <SelectMenu
                  value={severityFilter}
                  onValueChange={(value) => { setSeverityFilter(value as SeverityFilter); setCurrentPage(1); }}
                  options={severityOptions}
                  className="min-w-32"
                />
              </div>
              <div className="flex items-center justify-between gap-3 text-xs text-text-muted sm:justify-end">
                <span>{filteredSessions.length} matching session{filteredSessions.length === 1 ? "" : "s"}</span>
                {(query || severityFilter !== "All") && (
                  <button
                    onClick={() => { setQuery(""); setSeverityFilter("All"); setCurrentPage(1); }}
                    className="inline-flex items-center gap-1.5 font-medium text-primary hover:text-primary-action-hover"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                    Clear filters
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="relative h-[390px]">
          <div className="ui-scroll-region h-full" role="region" aria-label="Incursion directory table. Scroll to view all rows and columns." tabIndex={0}>
            <table className="ui-table min-w-[980px]">
              <thead>
                <tr>
                  {["SESSION ID", "ORIGIN IP", "ATTACKER TYPE", "SEVERITY", "DATE & TIME", "DURATION", "ACTION"].map((label) => (
                    <th key={label} scope="col" className={label === "ACTION" ? "text-right" : undefined}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {isInitialLoad && Array.from({ length: 5 }, (_, row) => (
                  <tr key={`loading-${row}`} aria-hidden="true">
                    {Array.from({ length: 7 }, (_, column) => <td key={column} className="h-[68px]"><div className="ui-skeleton h-4 w-full" /></td>)}
                  </tr>
                ))}
                {!isInitialLoad && currentData.map((session) => (
                  <tr key={session.id} className="group text-text-muted">
                    <td>
                      <span className="inline-flex items-center gap-2" title={session.id} aria-label={session.id} tabIndex={0}>
                        <span className={cn("h-2 w-2 shrink-0 rounded-full", severityDotClass(session.severity))} aria-hidden="true" />
                        <span className="font-mono text-sm font-medium text-text">{session.id.length > 12 ? `${session.id.substring(0, 10).toUpperCase()}…` : session.id.toUpperCase()}</span>
                      </span>
                    </td>
                    <td className="font-mono text-sm text-text">{session.sourceIp}</td>
                    <td><span className={cn("ui-badge", classificationBadgeClass(session.typeColor))}>{session.classification}</span></td>
                    <td><SeverityBadge severity={session.severity} /></td>
                    <td className="font-mono text-xs"><div className="text-text">{session.date}</div><div className="mt-1 text-text-subtle">{session.time}</div></td>
                    <td className="font-mono text-xs">{session.duration}</td>
                    <td className="text-right">
                      <Link href={`/threat-intel/${session.id}`} className="ui-button min-h-9 px-3 text-xs text-primary">
                        View Details
                        <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pointer-events-none absolute inset-x-0 top-[57px] bottom-0 p-4 sm:p-6 [&>div]:h-full">
            {renderedStatus === "error" && <RegionState kind="error" title="Sessions unavailable" description="We couldn’t load the session directory. The next automatic refresh will try again." />}
            {renderedStatus !== "loading" && renderedStatus !== "error" && renderedSessions.length === 0 && <RegionState kind="empty" title="No active sessions" description="No sessions were returned in the last successful response." />}
            {renderedStatus !== "loading" && renderedStatus !== "error" && renderedSessions.length > 0 && filteredSessions.length === 0 && <RegionState kind="empty" title="No matching sessions" description="Try a different search or severity filter." />}
          </div>
        </div>

        {filteredSessions.length > 0 && totalPages > 1 && (
          <nav aria-label="Directory pages" className="flex flex-wrap items-center gap-2 border-t border-border bg-surface-subtle p-4">
            <p className="mr-auto text-xs text-text-muted">Page {displayPage} of {totalPages}</p>
            <button disabled={displayPage === 1} onClick={() => setCurrentPage(displayPage - 1)} className="ui-button min-h-9 px-3 text-xs">
              <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
              Prev
            </button>
            {getPageNumbers().map((pageNumber) => (
              <button key={pageNumber} onClick={() => setCurrentPage(pageNumber)} aria-current={displayPage === pageNumber ? "page" : undefined} aria-label={`Page ${pageNumber}`} className="ui-button min-h-9 min-w-9 px-2 text-xs">
                {pageNumber}
              </button>
            ))}
            <button disabled={displayPage === totalPages} onClick={() => setCurrentPage(displayPage + 1)} className="ui-button min-h-9 px-3 text-xs">
              Next
              <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </nav>
        )}
      </section>
    </div>
  );
}

function severityBarClass(severity: string) {
  if (severity === "Critical") return "bg-danger";
  if (severity === "High" || severity === "Medium") return "bg-warning";
  return "bg-info";
}

function severityDotClass(severity: string) {
  if (severity === "Critical") return "bg-danger";
  if (severity === "High" || severity === "Medium") return "bg-warning";
  return "bg-info";
}

function formatUpdatedAt(timestamp: number | null) {
  if (!timestamp) return "Awaiting first response";
  return `Updated ${new Date(timestamp).toLocaleTimeString([], { hour12: false })}`;
}
