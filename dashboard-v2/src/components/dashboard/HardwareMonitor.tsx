"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CloudOff, Cpu, FlipHorizontal2, HardDrive, MemoryStick, Radio, RefreshCw, Thermometer, Wifi } from "lucide-react";

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
function formatBytes(value: number | string | null | undefined) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = Math.abs(value);
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${value < 0 ? "-" : ""}${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
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
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <MetricCard icon={Cpu} label="CPU usage" value={formatPercent(latest?.cpu_percent)} details={latest?.cpu_core_percent?.map((percentage, index) => ({ label: `Core ${index + 1}`, value: formatPercent(percentage) })) ?? []} />
        <MetricCard icon={MemoryStick} label="Memory" value={formatPercent(latest?.mem_percent)} details={[{ label: "Used", value: formatBytes(latest?.mem_used_bytes) }, { label: "Available", value: formatBytes(latest?.mem_available_bytes) }, { label: "Total", value: formatBytes(latest?.mem_total_bytes) }]} />
        <MetricCard icon={HardDrive} label="Storage" value={formatPercent(latest?.disk_percent)} details={[{ label: "Used", value: formatBytes(latest?.disk_used_bytes) }, { label: "Free", value: formatBytes(latest?.disk_free_bytes) }, { label: "Total", value: formatBytes(latest?.disk_total_bytes) }]} />
        <MetricCard icon={Thermometer} label="Temperature" value={formatTemperature(latest?.temperature)} details={[{ label: "Latest sample", value: latest?.time ?? "—" }, { label: "Reading", value: formatTemperature(latest?.temperature) }]} />
        <MetricCard icon={Wifi} label="wlan0 · RX / TX" value={`${formatThroughput(latest?.net_wlan0_rx_mbps)} / ${formatThroughput(latest?.net_wlan0_tx_mbps)}`} suffix="Mbps" details={[{ label: "RX", value: `${formatThroughput(latest?.net_wlan0_rx_mbps)} Mbps` }, { label: "TX", value: `${formatThroughput(latest?.net_wlan0_tx_mbps)} Mbps` }]} />
      </div>
      <div className="grid min-h-[220px] flex-1 grid-cols-1 gap-4 lg:grid-cols-3"><HardwareChart title="CPU history" description={`${metrics.length} most recent verified samples`} data={metrics} dataKey="cpu_percent" domain={[0, 100]} stroke="var(--chart-1)" fill="var(--chart-1-subtle)" /><HardwareChart title="Thermal history" description="Temperature in °C" data={metrics} dataKey="temperature" stroke="var(--warning)" fill="var(--warning-subtle)" /><ThroughputChart data={metrics} /></div>
    </div>}
  </div>;
}

type MetricDetail = { label: string; value: string };

function MetricCard({ icon: Icon, label, value, suffix, details, iconClassName = "bg-primary-subtle text-primary" }: { icon: typeof Cpu; label: string; value: string; suffix?: string; details: MetricDetail[]; iconClassName?: string }) {
  const [flipped, setFlipped] = useState(false);
  const accessibleDetails = details.filter((detail) => detail.value !== "—");
  const detailDescription = accessibleDetails.length > 0 ? accessibleDetails.map((detail) => `${detail.label}: ${detail.value}`).join(", ") : "No detailed value in the latest sample";

  return <button type="button" onClick={() => setFlipped((current) => !current)} aria-pressed={flipped} aria-label={`${label}. ${flipped ? "Show summary" : "Show details"}. ${flipped ? "" : detailDescription}`} className="group relative min-h-[104px] w-full text-left [perspective:1000px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2 focus-visible:ring-offset-surface">
    <span className={`relative block min-h-[104px] transition-transform duration-150 [transform-style:preserve-3d] motion-reduce:transition-none ${flipped ? "[transform:rotateY(180deg)] motion-reduce:[transform:none]" : ""}`}>
      <span className={`absolute inset-0 flex flex-col justify-between rounded-lg border border-border bg-surface-subtle p-3 shadow-[var(--shadow-card)] transition-colors duration-150 [backface-visibility:hidden] group-hover:border-border-strong group-hover:bg-surface-hover motion-reduce:[backface-visibility:visible] motion-reduce:transition-none ${flipped ? "motion-reduce:opacity-0" : "motion-reduce:opacity-100"}`}>
        <span className="flex min-w-0 items-center gap-3"><span className={`rounded-md p-2 ${iconClassName}`}><Icon className="h-4 w-4" aria-hidden="true" /></span><span className="min-w-0"><span className="block text-xs font-medium text-text-muted">{label}</span><span className="block truncate font-mono text-lg text-text">{value}{suffix && <span className="ml-1 text-xs text-text-subtle">{suffix}</span>}</span></span></span>
        <span className="inline-flex items-center gap-1 self-end text-xs text-text-subtle"><FlipHorizontal2 className="h-3.5 w-3.5" aria-hidden="true" />Details</span>
      </span>
      <span className={`absolute inset-0 flex flex-col justify-between rounded-lg border border-primary-border bg-primary-subtle p-3 [backface-visibility:hidden] [transform:rotateY(180deg)] motion-reduce:[backface-visibility:visible] motion-reduce:[transform:none] motion-reduce:transition-none ${flipped ? "motion-reduce:opacity-100" : "motion-reduce:opacity-0"}`}>
        <span className="flex min-w-0 items-center justify-between gap-2"><span className="text-xs font-medium text-text">{label} details</span><FlipHorizontal2 className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" /></span>
        {accessibleDetails.length > 0 ? <span className={`grid gap-x-2 gap-y-2 ${accessibleDetails.length > 3 ? "grid-cols-2" : "grid-cols-3"}`}>{accessibleDetails.map((detail) => <span key={detail.label} className="min-w-0"><span className="block truncate text-xs text-text-muted">{detail.label}</span><span className="block truncate font-mono text-xs font-medium text-text" title={detail.value}>{detail.value}</span></span>)}</span> : <span className="text-xs text-text-muted">No detailed value in the latest sample.</span>}
        <span className="self-end text-xs text-primary">Summary</span>
      </span>
    </span>
  </button>;
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
