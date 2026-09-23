"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ActivitySquare,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  Globe,
  Maximize,
  Minimize,
  Radio,
  RefreshCw,
  Server,
  ShieldCheck,
  Globe2,
  Ghost,
} from "lucide-react";
import AttackRateChart, { type ActivityPoint } from "@/components/dashboard/AttackRateChart";
import RegionalMap from "@/components/dashboard/RegionalMap";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState, RefreshStatus, type RegionStatus } from "@/components/ui/RegionState";
import type {
  DashboardThreatEvent,
  ThreatDashboardSummary,
} from "@/lib/dashboardTypes";
import { cn } from "@/lib/utils";

type RequestStatus = "loading" | "ready" | "error";

function buildActivityData(events: DashboardThreatEvent[], windowHours: number | null): ActivityPoint[] {
  const timestamps = events
    .map((event) => new Date(event.timestamp).getTime())
    .filter((timestamp) => Number.isFinite(timestamp))
    .sort((left, right) => left - right);
  if (!timestamps.length) return [];
  const latest = timestamps[timestamps.length - 1];
  const observedSpan = Math.max(latest - timestamps[0], 60 * 60 * 1_000);
  const range = windowHours && windowHours > 0 ? windowHours * 60 * 60 * 1_000 : observedSpan;
  const bucketCount = Math.min(6, Math.max(1, timestamps.length));
  const bucketSize = range / bucketCount;
  const start = latest - range;
  const buckets = Array.from({ length: bucketCount }, () => 0);
  timestamps.forEach((timestamp) => {
    if (timestamp < start) return;
    const index = Math.min(bucketCount - 1, Math.floor((timestamp - start) / bucketSize));
    buckets[index] += 1;
  });
  return buckets.map((rate, index) => ({
    time: new Date(start + (index + 1) * bucketSize).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    rate,
  }));
}

export default function DashboardPage() {
  const { threats: sessions, status, lastUpdated, refresh } = useThreatFeed();
  const mapPanel = useRef<HTMLDivElement>(null);
  const summaryRequest = useRef(0);
  const summaryRef = useRef<ThreatDashboardSummary | null>(null);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [isHydrated, setIsHydrated] = useState(false);
  const [summary, setSummary] = useState<ThreatDashboardSummary | null>(null);
  const [summaryStatus, setSummaryStatus] = useState<RequestStatus>("loading");

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setIsHydrated(true));
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const renderedSessions = useMemo(() => (isHydrated ? sessions : []), [isHydrated, sessions]);
  const renderedStatus = isHydrated ? status : "loading";
  const renderedLastUpdated = isHydrated ? lastUpdated : null;
  const isUpdating = renderedStatus === "loading" || renderedStatus === "refreshing";
  const isRefreshDisabled = !isHydrated || isUpdating;

  useEffect(() => {
    summaryRef.current = summary;
  }, [summary]);

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

  useEffect(() => {
    const timer = window.setTimeout(() => void loadSummary(), 0);
    return () => window.clearTimeout(timer);
  }, [loadSummary]);

  useEffect(() => {
    if (!lastUpdated) return;
    const timer = window.setTimeout(() => {
      void loadSummary();
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

  const feedState = statePresentation(renderedStatus);

  const activityData = useMemo(
    () => buildActivityData(renderedSessions, summary?.windowHours ?? null),
    [renderedSessions, summary?.windowHours]
  );

  const activeDeceptions = useMemo(() => {
    return renderedSessions.filter((entry) => entry.session_status === "active" || entry.duration === "Active").length;
  }, [renderedSessions]);

  const metrics = [
    {
      title: "Observed sessions",
      value: summary?.sessions,
      description: summary ? `In last ${summary.windowHours} hours` : "Awaiting summary",
      icon: ActivitySquare,
      tone: "info" as const,
      isLoading: summaryStatus === "loading",
      isError: summaryStatus === "error" && !summary,
    },
    {
      title: "Distinct sources",
      value: summary?.uniqueSources,
      description: summary ? "Unique origin IPs" : "Awaiting summary",
      icon: Globe,
      tone: "info" as const,
      isLoading: summaryStatus === "loading",
      isError: summaryStatus === "error" && !summary,
    },
    {
      title: "Active deceptions",
      value: isHydrated ? activeDeceptions : undefined,
      description: "Live interactive decoys",
      icon: Ghost,
      tone: "warning" as const,
      isLoading: renderedStatus === "loading",
      isError: renderedStatus === "error",
    },
    {
      title: "Feed status",
      value: feedState.metric,
      description: formatUpdatedAt(renderedLastUpdated),
      icon: Radio,
      tone: feedState.tone,
      isLoading: false,
      isError: false,
    },
  ];

  return (
    <div className="space-y-6 pb-12 font-sans">
      {/* Top Header */}
      <header className="flex flex-col justify-between gap-3 border-b border-border pb-4 sm:flex-row sm:items-end">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-info">
            <span>Operations</span>
            <span className="h-1 w-1 rounded-full bg-border-strong" aria-hidden="true" />
            <span className="inline-flex items-center gap-1.5 text-text-subtle font-normal">
              <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
              Live workspace
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-text sm:text-3xl">Overview Dashboard</h1>
          <p className="text-sm text-text-muted">Real-time telemetry and honeypot intrusion activity.</p>
        </div>
        <div className="flex items-center gap-3">
          <span role="status" aria-live="polite" className={cn("ui-badge text-xs font-medium", feedState.className)}>
            {renderedStatus === "refreshing" ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {feedState.label}
          </span>
          <RefreshStatus status={renderedStatus} />
          <button
            type="button"
            onClick={() => {
              void refresh();
              void loadSummary();
            }}
            disabled={isRefreshDisabled}
            className="ui-button min-h-9 px-3.5 text-xs font-medium"
            aria-label="Refresh dashboard data"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isUpdating && "animate-spin text-primary")} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </header>

      {/* KPI Cards */}
      <section aria-label="Situation summary" aria-busy={summaryStatus === "loading" || isUpdating} className="ui-panel overflow-hidden border border-border bg-surface">
        <dl className="grid grid-cols-1 divide-y divide-border sm:grid-cols-2 sm:divide-y-0 xl:grid-cols-4 xl:divide-x">
          {metrics.map(({ title, value, description, icon: Icon, tone, isLoading, isError }) => (
            <div key={title} className="flex items-center gap-4 px-5 py-4 transition-colors hover:bg-surface-hover/40">
              <span
                className={cn(
                  "grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-border/80",
                  tone === "danger"
                    ? "border-danger-border bg-danger-subtle text-danger"
                    : tone === "success"
                    ? "border-success-border bg-success-subtle text-success"
                    : tone === "warning"
                    ? "border-warning-border bg-warning-subtle text-warning"
                    : "border-info-border bg-info-subtle text-info"
                )}
              >
                <Icon className="h-5 w-5" aria-hidden="true" />
              </span>
              <div className="min-w-0 flex-1">
                <dt className="text-xs font-medium text-text-muted">{title}</dt>
                {isLoading ? (
                  <div className="mt-1 space-y-1" aria-label={`Loading ${title}`}>
                    <div className="ui-skeleton h-6 w-16" />
                  </div>
                ) : isError ? (
                  <div className="mt-1">
                    <dd className="text-xs font-medium text-danger">Unavailable</dd>
                  </div>
                ) : (
                  <>
                    <dd className={cn("mt-0.5 text-2xl font-bold leading-none tabular-nums", tone === "danger" && typeof value === "number" && value > 0 ? "text-danger" : "text-text")}>
                      {value ?? "—"}
                    </dd>
                    <dd className="mt-1 text-xs text-text-subtle truncate">{description}</dd>
                  </>
                )}
              </div>
            </div>
          ))}
        </dl>
      </section>

      {/* Row 1: Global Map & Attack Vector Summary */}
      <section aria-label="Live operational picture" className="space-y-4">
        <div>
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-info">Live Operational Picture</h2>
          <p className="mt-1 text-xs text-text-muted">Source geography and the most recent session observations.</p>
        </div>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-stretch">
          {/* Map Panel */}
          <div
            ref={mapPanel}
            role={isFullScreen ? "dialog" : undefined}
            aria-modal={isFullScreen ? true : undefined}
            aria-labelledby="distribution-title"
            className={cn(
              "ui-panel flex flex-col overflow-hidden border border-border bg-surface",
              isFullScreen ? "fixed inset-0 z-[100] h-dvh w-screen rounded-none" : "xl:col-span-8 h-[420px]"
            )}
          >
            <div className="flex flex-col sm:flex-row sm:items-start justify-between border-b border-border px-5 py-4 sm:px-6 gap-4">
              <div>
                <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-info mb-1.5">
                  <Globe className="h-4 w-4" aria-hidden="true" />
                  Global Telemetry
                </div>
                <h3 id="distribution-title" className="text-lg font-bold text-text">Global threat activity</h3>
                <p className="mt-1 text-xs text-text-muted">Observed source locations from the live session feed.</p>
              </div>
              <div className="flex items-center gap-4 text-xs text-text-muted sm:pt-2">
                <span className="inline-flex items-center gap-1.5 font-medium">
                  <span className="h-2.5 w-2.5 rotate-45 bg-danger" aria-hidden="true" />
                  Critical
                </span>
                <span className="inline-flex items-center gap-1.5 font-medium">
                  <span className="h-2.5 w-2.5 rounded-full bg-info" aria-hidden="true" />
                  Active
                </span>
                <button
                  onClick={() => setIsFullScreen((value) => !value)}
                  className="flex items-center justify-center rounded-md border border-border bg-surface h-8 w-8 text-text-subtle hover:bg-surface-hover hover:text-text transition-colors ml-1"
                  title={isFullScreen ? "Exit full screen" : "Open full screen"}
                  aria-label={isFullScreen ? "Exit full screen" : "Open full screen"}
                >
                  {isFullScreen ? <Minimize className="h-4 w-4" aria-hidden="true" /> : <Maximize className="h-4 w-4" aria-hidden="true" />}
                </button>
              </div>
            </div>
            <div className={cn("relative flex items-center justify-center overflow-hidden bg-surface-subtle", isFullScreen ? "min-h-0 flex-1" : "flex-1 min-h-0")}>
              <div className="relative h-full w-full overflow-hidden">
                <RegionalMap />
              </div>
            </div>
          </div>

          <AttackVectorSummaryPanel sessions={renderedSessions} status={renderedStatus} className="xl:col-span-4 h-[420px]" />
        </div>
      </section>

      {/* Row 2: Signal Review (Attack Trend + Live Threat Feed + Analyst Context) */}
      <section aria-label="Signal review" className="ui-panel overflow-hidden border border-border bg-surface shadow-xs">
        <div className="grid grid-cols-1 divide-y divide-border xl:grid-cols-12 xl:divide-x xl:divide-y-0">
          
          {/* ปรับเป็น xl:col-span-6 เพื่อให้กราฟกว้างครึ่งหนึ่งของหน้าจอ */}
          <article className="flex flex-col p-5 xl:col-span-6 h-[300px]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-info">
                  <BarChart3 className="h-4 w-4" aria-hidden="true" />
                  Attack Rate
                </div>
                <h3 className="mt-1 text-base font-semibold text-text">Activity Over Time</h3>
              </div>
              <span className="ui-badge text-xs border-info-border bg-info-subtle text-info">
                {summary ? `${summary.windowHours}h window` : "Observing"}
              </span>
            </div>
            <div className="mt-3 flex-1 min-h-0">
              <AttackRateChart data={activityData} />
            </div>
          </article>

          {/* ปรับลดลงเป็น xl:col-span-3 */}
          <div className="p-4 xl:col-span-3 h-[300px] flex flex-col">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-info mb-1">
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              Live Threat Feed
            </div>
            <h3 className="text-base font-semibold text-text mb-2">Recent Interceptions</h3>
            <div className="min-h-0 flex-1 divide-y divide-border/60 overflow-y-auto pr-1">
              {renderedSessions.slice(0, 3).map((session) => (
                <Link
                  key={session.id}
                  href={"/threat-intel/" + session.id}
                  className="group flex items-center justify-between gap-3 py-2 px-1 rounded transition-colors hover:bg-surface-hover/70"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono font-semibold text-primary truncate max-w-[100px]">{session.sourceIp}</span>
                      <span className="text-text-subtle font-mono text-[10px] shrink-0">({session.time})</span>
                    </div>
                    <div className="truncate text-[11px] text-text-muted mt-0.5">{session.sensor}</div>
                  </div>
                  <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-text-subtle group-hover:text-primary" aria-hidden="true" />
                </Link>
              ))}
            </div>
          </div>

          {/* ปรับลดลงเป็น xl:col-span-3 */}
          <div className="p-5 xl:col-span-3 flex flex-col justify-between bg-surface-subtle/30 h-[300px]">
            <AnalystInsightPanel summary={summary} status={summaryStatus} feedState={feedState} activeDeceptions={activeDeceptions} embedded />
          </div>
        </div>
      </section>
    </div>
  );
}

function AttackVectorSummaryPanel({ sessions, status, className }: { sessions: DashboardThreatEvent[]; status: RegionStatus; className?: string }) {
  const loading = status === "loading";
  const unavailable = status === "error";

  const topSensors = useMemo(() => {
    const counts = new Map<string, number>();
    sessions.forEach((log) => {
      const sensorName = log.sensor?.trim() || "Unknown Sensor";
      counts.set(sensorName, (counts.get(sensorName) ?? 0) + 1);
    });
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, count]) => ({
        name,
        count,
        percent: sessions.length > 0 ? Math.round((count / sessions.length) * 100) : 0,
      }));
  }, [sessions]);

  const topCountries = useMemo(() => {
    const counts = new Map<string, number>();
    sessions.forEach((log) => {
      const country = log.geo?.country?.trim() || "Unknown";
      counts.set(country, (counts.get(country) ?? 0) + 1);
    });
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([country, count]) => ({
        country,
        count,
        percent: sessions.length > 0 ? Math.round((count / sessions.length) * 100) : 0,
      }));
  }, [sessions]);

  return (
    <aside className={cn("ui-panel flex flex-col overflow-hidden border border-border shadow-xs bg-surface", className)} aria-labelledby="vector-summary-title">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-surface px-5 py-3">
        <div id="vector-summary-title" className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-info">
          <Server className="h-3.5 w-3.5" aria-hidden="true" />
          Attack Vector Summary
        </div>
        <span
          className={cn(
            "h-2 w-2 rounded-full",
            status === "error" ? "bg-danger" : status === "stale" ? "bg-warning" : status === "ready" ? "bg-success" : "bg-info"
          )}
        />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3.5 space-y-4">
        {loading && (
          <div className="space-y-3 py-6 text-center">
            <RegionState kind="loading" title="Compiling vectors..." />
          </div>
        )}
        {!loading && unavailable && <RegionState kind="error" title="Telemetry unavailable" />}
        {!loading && !unavailable && sessions.length === 0 && <RegionState kind="empty" title="No session metrics" />}
        {!loading && !unavailable && sessions.length > 0 && (
          <>
            <div>
              <div className="flex items-center justify-between text-xs font-semibold text-text-muted mb-2">
                <span className="flex items-center gap-1.5">
                  <Server className="h-3.5 w-3.5 text-primary" />
                  Top Targeted Sensors
                </span>
                <span>Hits</span>
              </div>
              <div className="space-y-2">
                {topSensors.map((item) => (
                  <div key={item.name} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-text truncate max-w-[150px]">{item.name}</span>
                      <span className="font-mono text-text-subtle text-xs">{item.count} ({item.percent}%)</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-border/60 overflow-hidden">
                      <div className="h-full rounded-full bg-primary" style={{ width: `${item.percent}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-border/70 pt-3">
              <div className="flex items-center justify-between text-xs font-semibold text-text-muted mb-2">
                <span className="flex items-center gap-1.5">
                  <Globe2 className="h-3.5 w-3.5 text-info" />
                  Top Origin Countries
                </span>
                <span>Traffic</span>
              </div>
              <div className="space-y-2">
                {topCountries.map((item) => (
                  <div key={item.country} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-text truncate max-w-[150px]">{item.country}</span>
                      <span className="font-mono text-text-subtle text-xs">{item.count} ({item.percent}%)</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-border/60 overflow-hidden">
                      <div className="h-full rounded-full bg-info" style={{ width: `${item.percent}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      <div className="border-t border-border bg-surface-subtle/50 p-2.5 text-center">
        <Link href="/threat-intel" className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline">
          <span>View full incursion feed &amp; directory</span>
          <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
        </Link>
      </div>
    </aside>
  );
}

function AnalystInsightPanel({
  summary,
  status,
  feedState,
  activeDeceptions,
}: {
  summary: ThreatDashboardSummary | null;
  status: RequestStatus;
  feedState: ReturnType<typeof statePresentation>;
  activeDeceptions: number;
  embedded?: boolean;
}) {
  return (
    <article className="flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-info">
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
          Security Context
        </div>
        <h3 className="text-sm font-semibold text-text mt-0.5">Analyst Briefing</h3>
      </div>
      <div className="my-auto py-2">
        {status === "loading" ? (
          <div className="space-y-2">
            <div className="ui-skeleton h-4 w-full" />
            <div className="ui-skeleton h-4 w-4/5" />
          </div>
        ) : status === "error" || !summary ? (
          <p className="text-xs text-danger">Briefing data unavailable.</p>
        ) : (
          <div className="rounded-lg border border-info-border/50 bg-info-subtle/30 p-3 text-[11px] leading-relaxed text-text">
            <p>
              Recorded <strong className="font-semibold">{summary.sessions.toLocaleString()} incursions</strong> from{" "}
              <strong className="font-semibold">{summary.uniqueSources.toLocaleString()} distinct IPs</strong> within{" "}
              <strong>{summary.windowHours}h</strong>.
            </p>
            <p className="mt-1 text-text-muted">
              Currently engaging <strong className="font-semibold text-text">{activeDeceptions}</strong> active deception sequences.
            </p>
          </div>
        )}
      </div>
      <div className="flex items-center justify-between border-t border-border/60 pt-1.5">
        <span className={cn("ui-badge text-[10px]", feedState.className)}>{feedState.label}</span>
        <Link href="/threat-intel" className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline">
          Investigate
          <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
        </Link>
      </div>
    </article>
  );
}

function statePresentation(status: RegionStatus) {
  if (status === "error") return { label: "Feed offline", metric: "Offline", tone: "danger" as const, className: "border-danger-border bg-danger-subtle text-danger" };
  if (status === "stale") return { label: "Feed stale", metric: "Stale", tone: "warning" as const, className: "border-warning-border bg-warning-subtle text-warning" };
  if (status === "refreshing") return { label: "Updating...", metric: "Updating", tone: "info" as const, className: "border-info-border bg-info-subtle text-info" };
  if (status === "loading") return { label: "Connecting...", metric: "Connecting", tone: "info" as const, className: "border-info-border bg-info-subtle text-info" };
  return { label: "Live", metric: "Connected", tone: "success" as const, className: "border-success-border bg-success-subtle text-success" };
}

function formatUpdatedAt(timestamp: number | null) {
  return timestamp ? `Updated ${new Date(timestamp).toLocaleTimeString([], { hour12: false })}` : "Awaiting first response";
}

function isThreatDashboardSummary(value: unknown): value is ThreatDashboardSummary {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const summary = value as Record<string, unknown>;
  return typeof summary.windowHours === "number" && typeof summary.sessions === "number" && typeof summary.uniqueSources === "number" && typeof summary.prioritySessions === "number";
}