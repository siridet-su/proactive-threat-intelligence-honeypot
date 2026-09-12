"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CloudOff, Cpu, HardDrive, MemoryStick, Radio, RefreshCw, Thermometer, Wifi } from "lucide-react";

import { formatHardwareMetric, isHardwareTelemetry, parseHardwareStreamMessage } from "@/lib/dashboardTypes";
import type { HardwareChartRecord, HardwareTelemetry } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";

const MAX_SAMPLES = 30;
const STALE_AFTER_MS = 30_000;

type ConnectionState = "connecting" | "live" | "fallback" | "unavailable";

function reconcileMetrics(incoming: HardwareTelemetry[], current: HardwareChartRecord[] = []) {
  const byTimestamp = new Map<number, HardwareChartRecord>();
  [...current, ...incoming.filter(isHardwareTelemetry).map(formatHardwareMetric)].forEach((metric) => byTimestamp.set(metric.timestampEpoch, metric));
  return Array.from(byTimestamp.values()).sort((left, right) => left.timestampEpoch - right.timestampEpoch).slice(-MAX_SAMPLES);
}

function formatPercent(value: number | string | null | undefined) { return typeof value === "number" ? `${value.toFixed(1)}%` : "—"; }
function formatTemperature(value: number | string | null | undefined) { return typeof value === "number" ? `${value.toFixed(1)}°C` : "—"; }
function formatThroughput(value: number | string | null | undefined) { return typeof value === "number" ? value.toFixed(2) : "—"; }
function formatAge(milliseconds: number) { if (milliseconds < 5_000) return "just now"; if (milliseconds < 60_000) return `${Math.floor(milliseconds / 1_000)}s ago`; return `${Math.floor(milliseconds / 60_000)}m ago`; }

export function HardwareMonitor() {
  const [metrics, setMetrics] = useState<HardwareChartRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [manualRefreshing, setManualRefreshing] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const refreshSnapshotRef = useRef<() => Promise<void>>(async () => undefined);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    let reconnectTimer: number | null = null;
    let fallbackTimer: number | null = null;
    let hasSnapshot = false;

    const receiveSnapshot = (incoming: HardwareTelemetry[]) => {
      hasSnapshot = true;
      setMetrics(reconcileMetrics(incoming));
      setFetchFailed(false);
      setLoading(false);
    };
    const receiveUpdate = (incoming: HardwareTelemetry) => {
      hasSnapshot = true;
      setMetrics((current) => reconcileMetrics([incoming], current));
      setFetchFailed(false);
      setLoading(false);
    };
    const fetchSnapshot = async () => {
      try {
        const response = await fetch("/api/hardware", { cache: "no-store" });
        if (!response.ok) throw new Error("Hardware request failed");
        const data: unknown = await response.json();
        if (!Array.isArray(data)) throw new Error("Hardware response unavailable");
        receiveSnapshot(data.filter(isHardwareTelemetry));
      } catch {
        if (!hasSnapshot) {
          setFetchFailed(true);
          setConnectionState("unavailable");
        }
      } finally {
        setLoading(false);
      }
    };
    refreshSnapshotRef.current = fetchSnapshot;

    const stopFallback = () => { if (fallbackTimer !== null) { window.clearInterval(fallbackTimer); fallbackTimer = null; } };
    const startFallback = () => {
      if (fallbackTimer !== null) return;
      setConnectionState("fallback");
      void fetchSnapshot();
      fallbackTimer = window.setInterval(() => void fetchSnapshot(), 15_000);
    };
    const scheduleReconnect = () => {
      if (disposed || reconnectTimer !== null) return;
      reconnectTimer = window.setTimeout(() => { reconnectTimer = null; connect(); }, 5_000);
    };
    const connect = () => {
      if (disposed) return;
      source?.close();
      setConnectionState(hasSnapshot ? "fallback" : "connecting");
      const connection = new EventSource("/api/hardware/stream");
      source = connection;
      connection.onmessage = (event) => {
        try {
          const message = parseHardwareStreamMessage(JSON.parse(event.data));
          if (!message) return;
          if (message.type === "initial") receiveSnapshot(message.data);
          else receiveUpdate(message.data);
        } catch {
          // Keep the last valid telemetry samples when a stream message is malformed.
        }
      };
      connection.onopen = () => { if (!disposed) { stopFallback(); setConnectionState("live"); } };
      connection.onerror = () => {
        if (disposed || source !== connection) return;
        connection.close();
        source = null;
        startFallback();
        scheduleReconnect();
      };
    };
    connect();
    return () => {
      disposed = true;
      source?.close();
      stopFallback();
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
    };
  }, []);

  const latest = metrics.at(-1) ?? null;
  const sampleAge = latest ? now - latest.timestampEpoch : null;
  const displayState = sampleAge !== null && sampleAge > STALE_AFTER_MS ? "stale" : connectionState;
  const statePresentation = useMemo(() => {
    if (displayState === "live") return { label: "Live", detail: "Streaming from hardware_live", className: "border-success-border bg-success-subtle text-success", iconClassName: "text-success", Icon: Radio };
    if (displayState === "fallback") return { label: "Polling fallback", detail: "Refreshing every 15 seconds", className: "border-warning-border bg-warning-subtle text-warning", iconClassName: "text-warning", Icon: RefreshCw };
    if (displayState === "stale") return { label: "Telemetry stale", detail: "Waiting for a newer hardware sample", className: "border-warning-border bg-warning-subtle text-warning", iconClassName: "text-warning", Icon: CloudOff };
    if (displayState === "unavailable") return { label: "Unavailable", detail: "Hardware service could not be reached", className: "border-danger-border bg-danger-subtle text-danger", iconClassName: "text-danger", Icon: CloudOff };
    return { label: "Connecting", detail: "Opening the telemetry stream", className: "border-info-border bg-info-subtle text-info", iconClassName: "text-info", Icon: RefreshCw };
  }, [displayState]);

  const refreshTelemetry = async () => {
    setManualRefreshing(true);
    try { await refreshSnapshotRef.current(); } finally { setManualRefreshing(false); }
  };

  return <div className="flex h-full flex-col gap-5">
    <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-start sm:justify-between">
      <div><div className="flex items-center gap-2"><statePresentation.Icon className={`h-4 w-4 ${statePresentation.iconClassName}`} aria-hidden="true" /><h2 className="text-base font-semibold">Hardware telemetry</h2></div><p className="mt-1 text-xs text-text-muted">{statePresentation.detail}{sampleAge !== null ? ` · latest sample ${formatAge(sampleAge)}` : ""}</p></div>
      <div className="flex items-center gap-2"><span className={`ui-badge ${statePresentation.className}`} aria-live="polite">{statePresentation.label}</span><button type="button" onClick={() => void refreshTelemetry()} disabled={manualRefreshing} className="ui-button min-h-9 px-3 text-xs"><RefreshCw className={`h-3.5 w-3.5 ${manualRefreshing ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />Refresh</button></div>
    </div>
    {loading && metrics.length === 0 ? <HardwareSkeleton /> : metrics.length === 0 ? <RegionState kind={fetchFailed ? "error" : "empty"} title={fetchFailed ? "Hardware telemetry unavailable" : "No hardware telemetry"} description={fetchFailed ? "The hardware service could not be reached. You can retry now or wait for the next automatic refresh." : "No verified telemetry samples were returned from hardware_live."} /> : <div className="flex min-h-0 flex-1 flex-col gap-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5"><MetricCard icon={Cpu} label="CPU usage" value={formatPercent(latest?.cpu_percent)} /><MetricCard icon={MemoryStick} label="Memory" value={formatPercent(latest?.mem_percent)} /><MetricCard icon={HardDrive} label="Storage" value={formatPercent(latest?.disk_percent)} /><MetricCard icon={Thermometer} label="Temperature" value={formatTemperature(latest?.temperature)} iconClassName="bg-warning-subtle text-warning" /><MetricCard icon={Wifi} label="wlan0 · RX / TX" value={`${formatThroughput(latest?.net_wlan0_rx_mbps)} / ${formatThroughput(latest?.net_wlan0_tx_mbps)}`} suffix="Mbps" /></div>
      <div className="grid min-h-[220px] flex-1 grid-cols-1 gap-4 lg:grid-cols-3"><HardwareChart title="CPU history" description={`${metrics.length} most recent verified samples`} data={metrics} dataKey="cpu_percent" domain={[0, 100]} stroke="var(--chart-1)" fill="var(--chart-1-subtle)" /><HardwareChart title="Thermal history" description="Temperature in °C" data={metrics} dataKey="temperature" stroke="var(--warning)" fill="var(--warning-subtle)" /><ThroughputChart data={metrics} /></div>
    </div>}
  </div>;
}

function MetricCard({ icon: Icon, label, value, suffix, iconClassName = "bg-primary-subtle text-primary" }: { icon: typeof Cpu; label: string; value: string; suffix?: string; iconClassName?: string }) {
  return <div className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3"><div className="flex items-center gap-3"><div className={`rounded-md p-2 ${iconClassName}`}><Icon className="h-4 w-4" aria-hidden="true" /></div><div className="min-w-0"><div className="text-xs font-medium text-text-muted">{label}</div><div className="truncate font-mono text-lg text-text">{value}{suffix && <span className="ml-1 text-xs text-text-subtle">{suffix}</span>}</div></div></div></div>;
}

function HardwareSkeleton() {
  return <div className="flex min-h-0 flex-1 flex-col gap-5" aria-busy="true" aria-label="Loading hardware telemetry"><div className="grid grid-cols-2 gap-3 lg:grid-cols-5">{Array.from({ length: 5 }, (_, index) => <div key={index} className="rounded-lg border border-border bg-surface-subtle p-3"><div className="flex items-center gap-3"><div className="ui-skeleton h-8 w-8" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-3 w-16" /><div className="ui-skeleton h-5 w-20" /></div></div></div>)}</div><div className="grid min-h-[220px] flex-1 grid-cols-1 gap-4 lg:grid-cols-3">{Array.from({ length: 3 }, (_, index) => <div key={index} className="flex flex-col rounded-lg border border-border bg-surface-subtle p-4"><div className="ui-skeleton mb-2 h-3 w-28" /><div className="ui-skeleton h-3 w-40" /><div className="ui-skeleton mt-4 flex-1" /></div>)}</div></div>;
}

function HardwareChart({ title, description, data, dataKey, stroke, fill, domain }: { title: string; description: string; data: HardwareChartRecord[]; dataKey: "cpu_percent" | "temperature"; stroke: string; fill: string; domain?: [number, number] }) {
  return <section className="flex min-h-[220px] flex-col rounded-lg border border-border bg-surface-subtle p-4" aria-label={title}><div><h3 className="text-xs font-medium text-text-muted">{title}</h3><p className="mt-1 text-xs text-text-subtle">{description}</p></div><div className="mt-3 min-h-0 flex-1"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data} margin={{ top: 5, right: 4, left: 2, bottom: 0 }}><CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} /><XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} /><YAxis stroke="var(--chart-axis)" fontSize={12} domain={domain} width={38} /><Tooltip contentStyle={{ backgroundColor: "var(--surface-raised)", borderColor: "var(--border)", color: "var(--text)", fontSize: "12px" }} /><Area type="monotone" dataKey={dataKey} stroke={stroke} strokeWidth={2} fillOpacity={1} fill={fill} isAnimationActive={false} connectNulls={false} /></AreaChart></ResponsiveContainer></div></section>;
}

function ThroughputChart({ data }: { data: HardwareChartRecord[] }) {
  return <section className="flex min-h-[220px] flex-col rounded-lg border border-border bg-surface-subtle p-4" aria-label="wlan0 throughput"><div><h3 className="text-xs font-medium text-text-muted">wlan0 throughput</h3><div className="mt-1 flex items-center gap-3 text-xs text-text-subtle"><span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[var(--chart-6)]" />RX</span><span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[var(--chart-1)]" />TX</span><span>Mbps</span></div></div><div className="mt-3 min-h-0 flex-1"><ResponsiveContainer width="100%" height="100%"><LineChart data={data} margin={{ top: 5, right: 4, left: 2, bottom: 0 }}><CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} /><XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} /><YAxis stroke="var(--chart-axis)" fontSize={12} width={38} /><Tooltip contentStyle={{ backgroundColor: "var(--surface-raised)", borderColor: "var(--border)", color: "var(--text)", fontSize: "12px" }} /><Line type="monotone" dataKey="net_wlan0_rx_mbps" name="RX (Mbps)" stroke="var(--chart-6)" strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} /><Line type="monotone" dataKey="net_wlan0_tx_mbps" name="TX (Mbps)" stroke="var(--chart-1)" strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} /></LineChart></ResponsiveContainer></div></section>;
}
