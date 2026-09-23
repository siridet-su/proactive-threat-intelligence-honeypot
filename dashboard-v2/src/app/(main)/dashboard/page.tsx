"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ActivitySquare,
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
  Info,
  Terminal,
} from "lucide-react";
import AttackRateChart, { type ActivityPoint } from "@/components/dashboard/AttackRateChart";
import RegionalMap from "@/components/dashboard/RegionalMap";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState, RefreshStatus, type RegionStatus } from "@/components/ui/RegionState";
import type {
  DashboardThreatEvent,
  ThreatDashboardSummary,
  DeceptionDecision,
} from "@/lib/dashboardTypes";
import { cn } from "@/lib/utils";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

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

interface CustomTooltipEntry {
  dataKey: string;
  name: string;
  value: number;
  color?: string;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: CustomTooltipEntry[];
  label?: string;
}

const CustomTooltip = ({ active, payload, label }: CustomTooltipProps) => {
  if (active && payload && payload.length) {
    const sortedPayload = [...payload].sort((a, b) => {
      const order: Record<string, number> = { "APT": 1, "ScriptKiddie": 2, "Bot": 3 };
      return (order[a.dataKey] ?? 99) - (order[b.dataKey] ?? 99);
    });

    return (
      <div className="bg-surface-raised border border-border rounded-lg shadow-lg p-3 text-xs text-text min-w-[150px]">
        <p className="font-bold mb-2 pb-2 border-b border-border/50">{label}</p>
        {sortedPayload.map((entry, index) => (
          <div key={index} className="flex justify-between items-center gap-4 py-1">
             <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }}></span>
                {entry.name}
             </span>
             <span className="font-bold">{entry.value}</span>
          </div>
        ))}
        <div className="flex justify-between items-center gap-4 pt-2 mt-2 border-t border-border/50 font-bold">
           <span>Total</span>
           <span>{payload.reduce((acc, curr) => acc + curr.value, 0)}</span>
        </div>
      </div>
    );
  }
  return null;
};

interface CustomXAxisTickProps {
  x?: string | number;
  y?: string | number;
  payload?: { value: string };
  data?: Array<{ time: string; total?: number; [key: string]: unknown }>;
  [key: string]: unknown;
}

const CustomXAxisTick = (props: CustomXAxisTickProps) => {
  const { x = 0, y = 0, payload, data = [] } = props;
  const dataPoint = payload ? data.find((d) => d.time === payload.value) : undefined;
  const isToday = payload?.value === "Today";

  return (
    <g transform={`translate(${x},${y})`}>
      {isToday && (
        <rect x={-20} y={4} width={40} height={20} rx={4} fill="var(--surface-hover)" />
      )}
      <text x={0} y={0} dy={18} textAnchor="middle" fill={isToday ? "var(--success)" : "var(--text)"} fontSize={12} fontWeight="600">
        {payload?.value}
      </text>
      <text x={0} y={0} dy={34} textAnchor="middle" fill="var(--text-subtle)" fontSize={11}>
        {dataPoint ? `${dataPoint.total} sess.` : "0 sess."}
      </text>
    </g>
  );
};

export default function DashboardPage() {
  const { threats: sessions, status, lastUpdated, refresh } = useThreatFeed();
  const mapPanel = useRef<HTMLDivElement>(null);
  const summaryRequest = useRef(0);
  const summaryRef = useRef<ThreatDashboardSummary | null>(null);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [isHydrated, setIsHydrated] = useState(false);
  const [summary, setSummary] = useState<ThreatDashboardSummary | null>(null);
  const [summaryStatus, setSummaryStatus] = useState<RequestStatus>("loading");
  
  const [deceptions, setDeceptions] = useState<DeceptionDecision[]>([]);

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

  const loadDeceptions = useCallback(async () => {
    try {
      const res = await fetch("/api/deception", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) setDeceptions(data);
      }
    } catch (e) {
      console.error("Failed to load deceptions", e);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadSummary();
      void loadDeceptions();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadSummary, loadDeceptions]);

  useEffect(() => {
    if (!lastUpdated) return;
    const timer = window.setTimeout(() => {
      void loadSummary();
      void loadDeceptions();
    }, 800);
    return () => window.clearTimeout(timer);
  }, [lastUpdated, loadSummary, loadDeceptions]);

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

  const dailyRiskData = useMemo(() => {
    const grouped = new Map<string, { time: string; timestamp: number; APT: number; Bot: number; ScriptKiddie: number; total: number; fullDate: Date }>();
    
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    for (let i = 6; i >= 0; i--) {
      const d = new Date(startOfToday);
      d.setDate(d.getDate() - i);
      const dateKey = d.toISOString().split("T")[0];
      const isToday = i === 0;
      grouped.set(dateKey, {
        time: isToday ? "Today" : d.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit" }),
        timestamp: d.getTime(),
        APT: 0,
        Bot: 0,
        ScriptKiddie: 0,
        total: 0,
        fullDate: d
      });
    }

    const cutoff = new Date(startOfToday);
    cutoff.setDate(cutoff.getDate() - 6);

    deceptions.forEach((d) => {
      if (!d.first_seen) return;
      const date = new Date(d.first_seen);
      if (isNaN(date.getTime()) || date < cutoff) return;

      const dateKey = new Date(date.getFullYear(), date.getMonth(), date.getDate()).toISOString().split("T")[0];

      if (grouped.has(dateKey)) {
        const bucket = grouped.get(dateKey)!;
        if (d.attacker_type === "APT") bucket.APT += 1;
        else if (d.attacker_type === "Bot") bucket.Bot += 1;
        else if (d.attacker_type === "ScriptKiddie") bucket.ScriptKiddie += 1;
        bucket.total += 1;
      }
    });

    return Array.from(grouped.values()).sort((a, b) => a.timestamp - b.timestamp);
  }, [deceptions]);

  const attackerSummary = useMemo(() => {
    let totalAPT = 0;
    let totalBot = 0;
    let totalScriptKiddie = 0;
    let total = 0;
    dailyRiskData.forEach(d => {
       totalAPT += d.APT;
       totalBot += d.Bot;
       totalScriptKiddie += d.ScriptKiddie;
       total += d.total;
    });
    return { totalAPT, totalBot, totalScriptKiddie, total };
  }, [dailyRiskData]);

  const dateRangeText = useMemo(() => {
    if (dailyRiskData.length === 0) return "";
    const first = dailyRiskData[0].time;
    const lastDate = dailyRiskData[dailyRiskData.length - 1].fullDate;
    const lastFormatted = lastDate.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit" });
    return `${first} – ${lastFormatted}`;
  }, [dailyRiskData]);

  const peakDay = useMemo(() => {
    if (dailyRiskData.length === 0) return null;
    let peak = dailyRiskData[0];
    dailyRiskData.forEach(d => {
      if (d.APT > peak.APT) peak = d;
    });
    return peak.APT > 0 ? peak : null;
  }, [dailyRiskData]);

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
        <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap sm:flex-nowrap">
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
              void loadDeceptions();
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
                  <div className="mt-1 space-y-1.5" aria-label={`Loading ${title}`}>
                    <div className="ui-skeleton h-6 w-20 rounded-md" />
                    <div className="ui-skeleton h-3 w-28 rounded-sm opacity-60" />
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

      <section aria-label="Live operational picture" className="space-y-4">
        <div>
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-info">Live Operational Picture</h2>
          <p className="mt-1 text-xs text-text-muted">Source geography and the most recent session observations.</p>
        </div>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-stretch">
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

      <section aria-label="Signal review" className="ui-panel overflow-hidden border border-border bg-surface shadow-xs">
        <div className="grid grid-cols-1 divide-y divide-border xl:grid-cols-12 xl:divide-x xl:divide-y-0">
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
              <AttackRateChart data={activityData} isLoading={summaryStatus === "loading"} />
            </div>
          </article>

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

          <div className="p-5 xl:col-span-3 flex flex-col justify-between bg-surface-subtle/30 h-[300px]">
            <AnalystInsightPanel summary={summary} status={summaryStatus} feedState={feedState} activeDeceptions={activeDeceptions} embedded />
          </div>
        </div>
      </section>

      <section aria-label="Daily attacker risk" className="space-y-4">
        <div>
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-danger">Risk Assessment</h2>
          <p className="mt-1 text-xs text-text-muted">Daily threat classification, risk level criteria, and TTP evidence.</p>
        </div>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-stretch">
          <article className="ui-panel flex flex-col overflow-hidden border border-border bg-surface shadow-xs xl:col-span-6 h-[460px]">
            <div className="flex shrink-0 flex-col sm:flex-row justify-between items-start border-b border-border px-5 py-4 gap-4">
              <div>
                 <h3 className="text-base font-semibold text-text tracking-tight">Daily Attacker Classification Trends</h3>
                 <p className="text-xs text-text-muted mt-1">
                   Session volume and risk proportion {dateRangeText}
                 </p>
              </div>
              <div className="flex items-center gap-3 text-xs font-medium bg-surface-subtle border border-border px-3 py-1.5 rounded-lg shrink-0">
                 <div className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-danger"></span>
                    <span className="text-text-muted">APT</span>
                 </div>
                 <div className="flex items-center gap-1.5 border-l border-border pl-3">
                    <span className="h-2 w-2 rounded-full bg-warning"></span>
                    <span className="text-text-muted">Script Kiddie</span>
                 </div>
                 <div className="flex items-center gap-1.5 border-l border-border pl-3">
                    <span className="h-2 w-2 rounded-full bg-info"></span>
                    <span className="text-text-muted">Scanner</span>
                 </div>
              </div>
            </div>
             
            <div className="flex-1 min-h-0 w-full p-4">
               <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={dailyRiskData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }} barSize={32}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border)" opacity={0.6} />
                      <XAxis dataKey="time" tickLine={false} axisLine={false} tick={(props) => <CustomXAxisTick {...props} data={dailyRiskData} />} />
                      <YAxis hide />
                      <Tooltip content={<CustomTooltip />} cursor={{ fill: 'var(--surface-hover)', opacity: 0.5 }} />
                      
                      <Bar dataKey="Bot" name="Scanners (Low)" stackId="a" fill="var(--info)" radius={[0, 0, 4, 4]} />
                      <Bar dataKey="ScriptKiddie" name="Script Kiddie (Med)" stackId="a" fill="var(--warning)" />
                      <Bar dataKey="APT" name="APT (Critical)" stackId="a" fill="var(--danger)" radius={[4, 4, 0, 0]} />
                  </BarChart>
               </ResponsiveContainer>
            </div>
             
            <div className="border-t border-border bg-surface-subtle/50 px-5 py-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
               {peakDay ? (
                  <div className="flex items-center gap-2 text-xs">
                      <span className="h-2 w-2 rounded-full bg-danger shrink-0 animate-pulse"></span>
                      <span className="font-semibold text-text-muted">
                        APT Peak Alert: <span className="font-normal text-text">Intrusion attempts on {peakDay.time === "Today" ? peakDay.fullDate.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit" }) : peakDay.time} ({peakDay.APT} events)</span>
                      </span>
                  </div>
               ) : (
                  <div className="text-xs text-text-muted italic">No critical APT alerts in the last 7 days.</div>
               )}
               <div className="text-xs font-mono font-medium text-text bg-surface px-2.5 py-1 rounded border border-border shadow-xs">
                  7-day volume: <strong className="font-bold">{attackerSummary.total}</strong>
               </div>
            </div>
          </article>

          <aside className="ui-panel flex flex-col overflow-hidden border border-border bg-surface shadow-xs xl:col-span-3 h-[460px]" aria-labelledby="risk-criteria-title">
            <div className="flex shrink-0 items-center justify-between border-b border-border bg-surface px-5 py-3">
               <div id="risk-criteria-title" className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-primary">
                  <Info className="h-3.5 w-3.5" aria-hidden="true" />
                  Risk Level Criteria
               </div>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-surface-subtle/30">
                <div className="border border-danger-border bg-danger-subtle/40 rounded-xl p-4 flex flex-col hover:bg-danger-subtle/80 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2 font-bold text-danger text-sm">
                            <span className="h-2.5 w-2.5 rounded-full bg-danger"></span>
                            APT
                        </div>
                        <span className="bg-danger text-white text-[10px] font-bold px-2 py-0.5 rounded shadow-sm">CRITICAL</span>
                    </div>
                    <div className="text-2xl font-bold text-danger tabular-nums border-t border-danger-border/50 pt-2 mt-2">
                      {attackerSummary.totalAPT} <span className="text-xs font-medium text-danger/70 tracking-wide uppercase">sessions</span>
                    </div>
                </div>

                <div className="border border-warning-border bg-warning-subtle/40 rounded-xl p-4 flex flex-col hover:bg-warning-subtle/80 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2 font-bold text-warning text-sm">
                            <span className="h-2.5 w-2.5 rounded-full bg-warning"></span>
                            Script Kiddie
                        </div>
                        <span className="bg-warning text-white text-[10px] font-bold px-2 py-0.5 rounded shadow-sm">MEDIUM</span>
                    </div>
                    <div className="text-2xl font-bold text-warning tabular-nums border-t border-warning-border/50 pt-2 mt-2">
                      {attackerSummary.totalScriptKiddie} <span className="text-xs font-medium text-warning/70 tracking-wide uppercase">sessions</span>
                    </div>
                </div>

                <div className="border border-info-border bg-info-subtle/40 rounded-xl p-4 flex flex-col hover:bg-info-subtle/80 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2 font-bold text-info text-sm">
                            <span className="h-2.5 w-2.5 rounded-full bg-info"></span>
                            Scanners
                        </div>
                        <span className="bg-info text-white text-[10px] font-bold px-2 py-0.5 rounded shadow-sm">LOW</span>
                    </div>
                    <div className="text-2xl font-bold text-info tabular-nums border-t border-info-border/50 pt-2 mt-2">
                      {attackerSummary.totalBot} <span className="text-xs font-medium text-info/70 tracking-wide uppercase">sessions</span>
                    </div>
                </div>
            </div>
          </aside>

          <TopTTPsPanel sessions={renderedSessions} className="xl:col-span-3 h-[460px]" />
        </div>
      </section>
    </div>
  );
}

function TopTTPsPanel({ sessions, className }: { sessions: DashboardThreatEvent[]; className?: string }) {
  const [topTTPs, setTopTTPs] = useState<{ name: string; count: number; percent: number }[]>([]);
  const [isTtpLoading, setIsTtpLoading] = useState(sessions.length > 0);

  useEffect(() => {
    if (sessions.length === 0) {
      return;
    }
    let isCancelled = false;

    const fetchTTPs = async () => {
      setIsTtpLoading(true);
      const sampleSessions = sessions.slice(0, 10);
      const counts = new Map<string, number>();
      let totalFound = 0;

      await Promise.all(sampleSessions.map(async (s) => {
        try {
          const res = await fetch(`/api/sessions/${s.id}/commands`);
          if (res.ok) {
            const data = await res.json();
            if (data.commands && Array.isArray(data.commands)) {
              data.commands.forEach((cmd: Record<string, unknown>) => {
                const ttp = cmd.classification_technique;
                if (ttp && typeof ttp === "string") {
                  counts.set(ttp, (counts.get(ttp) || 0) + 1);
                  totalFound++;
                } else if (Array.isArray(cmd.classification)) {
                  cmd.classification.forEach((c: Record<string, unknown>) => {
                    if (c.ttp && typeof c.ttp === "string") {
                      counts.set(c.ttp, (counts.get(c.ttp) || 0) + 1);
                      totalFound++;
                    }
                  });
                }
              });
            }
          }
        } catch {
          // Ignore fetch errors
        }
      }));

      if (!isCancelled) {
        const sorted = Array.from(counts.entries())
          .map(([name, count]) => ({
            name: `MITRE: ${name}`,
            count,
            percent: totalFound > 0 ? Math.round((count / totalFound) * 100) : 0
          }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 5);
        
        setTopTTPs(sorted);
        setIsTtpLoading(false);
      }
    };

    void fetchTTPs();
    return () => { isCancelled = true; };
  }, [sessions]);

  return (
    <aside className={cn("ui-panel flex flex-col overflow-hidden border border-border shadow-xs bg-surface", className)}>
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-surface px-5 py-3">
         <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-warning">
            <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
            Top TTPs (MITRE ATT&CK)
         </div>
      </div>
      
      <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-surface-subtle/30">
        {isTtpLoading ? (
          <div className="space-y-4 pt-1">
            <div className="space-y-1.5"><div className="ui-skeleton h-4 w-full" /><div className="ui-skeleton h-1.5 w-full rounded-full" /></div>
            <div className="space-y-1.5"><div className="ui-skeleton h-4 w-4/5" /><div className="ui-skeleton h-1.5 w-full rounded-full" /></div>
            <div className="space-y-1.5"><div className="ui-skeleton h-4 w-3/4" /><div className="ui-skeleton h-1.5 w-full rounded-full" /></div>
          </div>
        ) : topTTPs.length > 0 ? (
          <div className="space-y-5">
            {topTTPs.map((item) => (
              <div key={item.name} className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-text truncate max-w-[150px] sm:max-w-[180px]">{item.name}</span>
                  <span className="font-mono text-text-subtle text-[11px]">{item.count} ({item.percent}%)</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-border/60 overflow-hidden">
                  <div className="h-full rounded-full bg-warning" style={{ width: `${item.percent}%` }} />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-center text-text-subtle">
            <Terminal className="h-8 w-8 mb-2 opacity-20" />
            <p className="text-[11px] italic">No TTP evidence extracted<br/>from recent commands.</p>
          </div>
        )}
      </div>
    </aside>
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
          <div className="space-y-4 py-2" aria-label="Compiling attack vectors">
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="ui-skeleton h-3.5 w-32" />
                <div className="ui-skeleton h-3.5 w-10" />
              </div>
              {[72, 45, 24].map((pct, i) => (
                <div key={i} className="space-y-1.5">
                  <div className="flex justify-between">
                    <div className="ui-skeleton h-3 w-24" />
                    <div className="ui-skeleton h-3 w-12" />
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-border/60 overflow-hidden">
                    <div className="ui-skeleton h-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
            <div className="border-t border-border/70 pt-3 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="ui-skeleton h-3.5 w-32" />
                <div className="ui-skeleton h-3.5 w-10" />
              </div>
              {[58, 34, 16].map((pct, i) => (
                <div key={i} className="space-y-1.5">
                  <div className="flex justify-between">
                    <div className="ui-skeleton h-3 w-24" />
                    <div className="ui-skeleton h-3 w-12" />
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-border/60 overflow-hidden">
                    <div className="ui-skeleton h-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
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
