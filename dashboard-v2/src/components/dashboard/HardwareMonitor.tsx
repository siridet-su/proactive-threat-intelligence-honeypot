"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, CloudOff, Cpu, HardDrive, MemoryStick, Radio, RefreshCw, Thermometer, Wifi } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

import { formatHardwareMetric, isHardwareTelemetry, parseHardwareStreamMessage } from "@/lib/dashboardTypes";
import type { HardwareChartRecord, HardwareTelemetry } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";
import { ChartLaserLoader } from "@/components/ui/loaders";

const MAX_SAMPLES = 30;
const STALE_AFTER_MS = 30_000;

type ConnectionState = "connecting" | "live" | "fallback" | "unavailable";
type MetricTone = "normal" | "watch" | "critical" | "neutral";

type LiveLine = {
  dataKey: string;
  name: string;
  color: string;
  fill?: string;
};

function reconcileMetrics(incoming: HardwareTelemetry[], current: HardwareChartRecord[] = []) {
  const byTimestamp = new Map<number, HardwareChartRecord>();
  [...current, ...incoming.filter(isHardwareTelemetry).map(formatHardwareMetric)].forEach((metric) => byTimestamp.set(metric.timestampEpoch, metric));
  return Array.from(byTimestamp.values()).sort((left, right) => left.timestampEpoch - right.timestampEpoch).slice(-MAX_SAMPLES);
}

function numericValue(value: number | string | null | undefined) {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function formatPercent(value: number | string | null | undefined) {
  const numeric = numericValue(value);
  return numeric === null ? "—" : `${numeric.toFixed(1)}%`;
}

function formatTemperature(value: number | string | null | undefined) {
  const numeric = numericValue(value);
  return numeric === null ? "—" : `${numeric.toFixed(1)}°C`;
}

function formatThroughput(value: number | string | null | undefined) {
  const numeric = numericValue(value);
  return numeric === null ? "—" : numeric.toFixed(2);
}

function formatBytes(value: number | string | null | undefined) {
  const numeric = numericValue(value);
  if (numeric === null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = Math.abs(numeric);
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${numeric < 0 ? "-" : ""}${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function memoryPercent(metric: HardwareTelemetry | null | undefined) {
  return metric?.mem_pressure_percent ?? metric?.mem_percent;
}

function memoryUsedBytes(metric: HardwareTelemetry | null | undefined) {
  const direct = numericValue(metric?.mem_used_bytes);
  if (direct !== null) return direct;
  const total = numericValue(metric?.mem_total_bytes);
  const available = numericValue(metric?.mem_available_bytes);
  return total !== null && available !== null ? Math.max(0, total - available) : null;
}

function diskUsedBytes(metric: HardwareTelemetry | null | undefined) {
  const direct = numericValue(metric?.disk_used_bytes);
  if (direct !== null) return direct;
  const total = numericValue(metric?.disk_total_bytes);
  const free = numericValue(metric?.disk_free_bytes);
  return total !== null && free !== null ? Math.max(0, total - free) : null;
}

function formatAge(milliseconds: number) {
  const age = Math.max(0, milliseconds);
  if (age < 5_000) return "just now";
  if (age < 60_000) return `${Math.floor(age / 1_000)}s ago`;
  return `${Math.floor(age / 60_000)}m ago`;
}

function formatDelta(current: number | string | null | undefined, previous: number | string | null | undefined, digits = 1) {
  const currentValue = numericValue(current);
  const previousValue = numericValue(previous);
  if (currentValue === null || previousValue === null) return "No prior sample";
  const delta = currentValue - previousValue;
  if (Math.abs(delta) < 0.05) return "Stable";
  return `${delta > 0 ? "+" : ""}${delta.toFixed(digits)} from prior`;
}

function pressureTone(value: number | string | null | undefined): MetricTone {
  const numeric = numericValue(value);
  if (numeric === null) return "neutral";
  if (numeric >= 90) return "critical";
  if (numeric >= 75) return "watch";
  return "normal";
}

function temperatureTone(value: number | string | null | undefined): MetricTone {
  const numeric = numericValue(value);
  if (numeric === null) return "neutral";
  if (numeric >= 80) return "critical";
  if (numeric >= 70) return "watch";
  return "normal";
}

function toneClasses(tone: MetricTone) {
  if (tone === "critical") return {
    border: "border-danger-border",
    icon: "bg-danger-subtle text-danger",
    dot: "bg-danger",
    text: "text-danger",
  };
  if (tone === "watch") return {
    border: "border-warning-border",
    icon: "bg-warning-subtle text-warning",
    dot: "bg-warning",
    text: "text-warning",
  };
  if (tone === "normal") return {
    border: "border-success-border/70",
    icon: "bg-success-subtle text-success",
    dot: "bg-success",
    text: "text-success",
  };
  return {
    border: "border-border",
    icon: "bg-primary-subtle text-primary",
    dot: "bg-text-subtle",
    text: "text-text-subtle",
  };
}

function healthSummary(latest: HardwareTelemetry | null, displayState: ConnectionState | "stale") {
  if (displayState === "unavailable") return { label: "Unavailable", detail: "Hardware service is not responding", tone: "critical" as MetricTone };
  if (displayState === "stale") return { label: "Needs attention", detail: "Waiting for a newer hardware sample", tone: "watch" as MetricTone };
  if (!latest) return { label: "Awaiting sample", detail: "Opening the hardware telemetry stream", tone: "neutral" as MetricTone };

  const pressures = [latest.cpu_percent, memoryPercent(latest), latest.disk_percent]
    .map(numericValue)
    .filter((value): value is number => value !== null);
  const temperature = numericValue(latest.temperature);
  const highestPressure = pressures.length > 0 ? Math.max(...pressures) : 0;
  if (highestPressure >= 90 || (temperature !== null && temperature >= 80)) return { label: "Critical load", detail: "One or more hardware signals are elevated", tone: "critical" as MetricTone };
  if (highestPressure >= 75 || (temperature !== null && temperature >= 70)) return { label: "Watch signals", detail: "Hardware is operating above the normal band", tone: "watch" as MetricTone };
  return { label: "Within expected range", detail: "Live hardware signals are stable", tone: "normal" as MetricTone };
}

export function HardwareMonitor() {
  const [metrics, setMetrics] = useState<HardwareChartRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [manualRefreshing, setManualRefreshing] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const refreshSnapshotRef = useRef<() => Promise<void>>(async () => undefined);
  const shouldReduceMotion = useReducedMotion();

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

    const stopFallback = () => {
      if (fallbackTimer !== null) {
        window.clearInterval(fallbackTimer);
        fallbackTimer = null;
      }
    };
    const startFallback = () => {
      if (fallbackTimer !== null) return;
      setConnectionState("fallback");
      void fetchSnapshot();
      fallbackTimer = window.setInterval(() => void fetchSnapshot(), 15_000);
    };
    const scheduleReconnect = () => {
      if (disposed || reconnectTimer !== null) return;
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, 5_000);
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
      connection.onopen = () => {
        if (!disposed) {
          stopFallback();
          setConnectionState("live");
        }
      };
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
  const previous = metrics.length > 1 ? metrics.at(-2) ?? null : null;
  const sampleAge = latest ? now - latest.timestampEpoch : null;
  const displayState: ConnectionState | "stale" = sampleAge !== null && sampleAge > STALE_AFTER_MS ? "stale" : connectionState;
  const statePresentation = useMemo(() => {
    if (displayState === "live") return { label: "Live", detail: "Streaming from hardware_live", className: "border-success-border bg-success-subtle text-success", iconClassName: "text-success", Icon: Radio };
    if (displayState === "fallback") return { label: "Polling fallback", detail: "Refreshing every 15 seconds", className: "border-warning-border bg-warning-subtle text-warning", iconClassName: "text-warning", Icon: RefreshCw };
    if (displayState === "stale") return { label: "Telemetry stale", detail: "Waiting for a newer hardware sample", className: "border-warning-border bg-warning-subtle text-warning", iconClassName: "text-warning", Icon: CloudOff };
    if (displayState === "unavailable") return { label: "Unavailable", detail: "Hardware service could not be reached", className: "border-danger-border bg-danger-subtle text-danger", iconClassName: "text-danger", Icon: CloudOff };
    return { label: "Connecting", detail: "Opening the telemetry stream", className: "border-info-border bg-info-subtle text-info", iconClassName: "text-info", Icon: RefreshCw };
  }, [displayState]);
  const health = useMemo(() => healthSummary(latest, displayState), [displayState, latest]);
  const healthStyles = toneClasses(health.tone);

  const refreshTelemetry = async () => {
    setManualRefreshing(true);
    try {
      await refreshSnapshotRef.current();
    } finally {
      setManualRefreshing(false);
    }
  };

  return (
    <section className="ui-panel overflow-hidden p-4 sm:p-5">
      <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${healthStyles.icon}`}>
              <Activity className="h-4 w-4" aria-hidden="true" />
            </span>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold text-text">Live telemetry</h2>
                <span className={`ui-badge ${statePresentation.className}`} aria-live="polite">
                  <statePresentation.Icon className={`h-3.5 w-3.5 ${statePresentation.iconClassName} ${displayState === "connecting" || displayState === "fallback" ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
                  {statePresentation.label}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-muted">{statePresentation.detail}{sampleAge !== null ? ` · latest sample ${formatAge(sampleAge)}` : ""}</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start">
          <div className={`hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs sm:flex ${healthStyles.border} ${healthStyles.text}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${healthStyles.dot}`} aria-hidden="true" />
            {health.label}
          </div>
          <button type="button" onClick={() => void refreshTelemetry()} disabled={manualRefreshing} className="ui-button min-h-9 px-3 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${manualRefreshing ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {loading && metrics.length === 0 ? (
        <HardwareSkeleton />
      ) : metrics.length === 0 ? (
        <div className="mt-4">
          <RegionState kind={fetchFailed ? "error" : "empty"} title={fetchFailed ? "Hardware telemetry unavailable" : "No hardware telemetry"} description={fetchFailed ? "The hardware service could not be reached. Retry now or wait for the next automatic refresh." : "No verified telemetry samples were returned from hardware_live."} />
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-5">
            <MetricCard index={0} icon={Cpu} label="CPU usage" value={formatPercent(latest?.cpu_percent)} detail={`${latest?.cpu_core_percent?.length ?? "—"} logical cores`} delta={formatDelta(latest?.cpu_percent, previous?.cpu_percent)} tone={pressureTone(latest?.cpu_percent)} reduceMotion={Boolean(shouldReduceMotion)} />
            <MetricCard index={1} icon={MemoryStick} label="Memory pressure" value={formatPercent(memoryPercent(latest))} detail={`${formatBytes(memoryUsedBytes(latest))} used · ${formatBytes(latest?.mem_available_bytes)} free`} delta={formatDelta(memoryPercent(latest), memoryPercent(previous))} tone={pressureTone(memoryPercent(latest))} reduceMotion={Boolean(shouldReduceMotion)} />
            <MetricCard index={2} icon={HardDrive} label="Storage" value={formatPercent(latest?.disk_percent)} detail={`${formatBytes(diskUsedBytes(latest))} used · ${formatBytes(latest?.disk_free_bytes)} free`} delta={formatDelta(latest?.disk_percent, previous?.disk_percent)} tone={pressureTone(latest?.disk_percent)} reduceMotion={Boolean(shouldReduceMotion)} />
            <MetricCard index={3} icon={Thermometer} label="Temperature" value={formatTemperature(latest?.temperature)} detail="Thermal probe" delta={formatDelta(latest?.temperature, previous?.temperature)} tone={temperatureTone(latest?.temperature)} reduceMotion={Boolean(shouldReduceMotion)} />
            <MetricCard index={4} icon={Wifi} label="wlan0 throughput" value={`${formatThroughput(latest?.net_wlan0_rx_mbps)} / ${formatThroughput(latest?.net_wlan0_tx_mbps)}`} unit="RX / TX Mbps" detail="Virtual network interface" delta={`${formatThroughput(latest?.net_wlan0_rx_mbps)} / ${formatThroughput(latest?.net_wlan0_tx_mbps)} Mbps`} tone="neutral" reduceMotion={Boolean(shouldReduceMotion)} />
          </div>

          <div className="grid gap-3 lg:grid-cols-[minmax(0,1.35fr)_minmax(230px,0.65fr)] lg:grid-rows-2">
            <LiveChart
              title="System pressure"
              description="CPU, memory, and storage use"
              data={metrics}
              lines={[
                { dataKey: "cpu_percent", name: "CPU", color: "var(--chart-1)", fill: "var(--chart-1)" },
                { dataKey: "mem_pressure_percent", name: "Memory", color: "var(--chart-6)" },
                { dataKey: "disk_percent", name: "Storage", color: "var(--chart-3)" },
              ]}
              domain={[0, 100]}
              mode="area"
              className="min-h-[250px] lg:row-span-2"
            />
            <LiveChart title="Thermal signal" description="Temperature in °C" data={metrics} lines={[{ dataKey: "temperature", name: "Temperature", color: "var(--warning)", fill: "var(--warning)" }]} mode="area" className="min-h-[154px]" />
            <LiveChart title="wlan0 throughput" description="RX / TX Mbps" data={metrics} lines={[{ dataKey: "net_wlan0_rx_mbps", name: "RX", color: "var(--chart-6)" }, { dataKey: "net_wlan0_tx_mbps", name: "TX", color: "var(--chart-1)" }]} mode="line" className="min-h-[154px]" />
          </div>
        </div>
      )}
    </section>
  );
}

type MetricDetailProps = {
  index: number;
  icon: typeof Cpu;
  label: string;
  value: string;
  unit?: string;
  detail: string;
  delta: string;
  tone: MetricTone;
  reduceMotion: boolean;
};

function MetricCard({ index, icon: Icon, label, value, unit, detail, delta, tone, reduceMotion }: MetricDetailProps) {
  const styles = toneClasses(tone);
  return (
    <motion.article
      initial={reduceMotion ? false : { opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={reduceMotion ? { duration: 0 } : { duration: 0.22, delay: index * 0.035, ease: [0.22, 1, 0.36, 1] }}
      className={`min-w-0 rounded-xl border bg-surface-subtle p-3 ${styles.border}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${styles.icon}`}>
          <Icon className="h-4 w-4" aria-hidden="true" />
        </span>
        <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${styles.dot}`} title={tone === "neutral" ? "Informational signal" : tone} aria-label={tone === "neutral" ? "Informational signal" : tone} />
      </div>
      <p className="mt-3 truncate text-[11px] font-medium text-text-muted" title={label}>{label}</p>
      <p className="mt-0.5 truncate font-mono text-[17px] font-semibold tabular-nums text-text" title={`${value}${unit ? ` ${unit}` : ""}`}>
        {value}
        {unit && <span className="ml-1 text-[10px] font-medium text-text-subtle">{unit}</span>}
      </p>
      <div className="mt-2 flex min-w-0 items-center justify-between gap-2 text-[10px] text-text-subtle">
        <span className="truncate" title={detail}>{detail}</span>
        <span className="shrink-0 tabular-nums" title={delta}>{delta}</span>
      </div>
    </motion.article>
  );
}

function HardwareSkeleton() {
  return (
    <div className="mt-4 space-y-4" aria-busy="true" aria-label="Loading hardware telemetry">
      <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-5">
        {Array.from({ length: 5 }, (_, index) => (
          <div key={index} className="rounded-xl border border-border bg-surface-subtle p-3">
            <div className="ui-skeleton h-8 w-8 rounded-lg" />
            <div className="mt-3 space-y-2">
              <div className="ui-skeleton h-3 w-20" />
              <div className="ui-skeleton h-5 w-24" />
              <div className="ui-skeleton h-2.5 w-full" />
            </div>
          </div>
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.35fr)_minmax(230px,0.65fr)] lg:grid-rows-2">
        <ChartLaserLoader title="Calibrating system pressure…" />
        <ChartLaserLoader title="Calibrating thermal signal…" />
        <ChartLaserLoader title="Calibrating network signal…" />
      </div>
    </div>
  );
}

function ChartDecorations({ domain }: { domain?: [number, number] }) {
  return (
    <>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
      <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={10} tickMargin={8} minTickGap={34} axisLine={false} tickLine={false} />
      <YAxis stroke="var(--chart-axis)" fontSize={10} domain={domain} width={34} axisLine={false} tickLine={false} />
      <Tooltip cursor={{ stroke: "var(--border-strong)", strokeDasharray: "4 4" }} contentStyle={{ backgroundColor: "var(--surface-raised)", borderColor: "var(--border)", borderRadius: "10px", color: "var(--text)", fontSize: "11px" }} />
    </>
  );
}

function LiveChart({ title, description, data, lines, domain, mode, className }: { title: string; description: string; data: HardwareChartRecord[]; lines: LiveLine[]; domain?: [number, number]; mode: "area" | "line"; className?: string }) {
  return (
    <section className={`flex flex-col rounded-xl border border-border bg-surface-subtle p-3.5 ${className ?? ""}`} aria-label={title}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="text-xs font-semibold text-text">{title}</h3>
          <p className="mt-0.5 text-[11px] text-text-subtle">{description}</p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-x-2.5 gap-y-1 text-[10px] text-text-subtle">
          {lines.map((line) => <span key={line.dataKey} className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: line.color }} />{line.name}</span>)}
        </div>
      </div>
      <div className="mt-2 min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          {mode === "line" ? (
            <LineChart data={data} margin={{ top: 6, right: 4, left: -8, bottom: 0 }}>
              <ChartDecorations domain={domain} />
              {lines.map((line) => <Line key={line.dataKey} type="monotone" dataKey={line.dataKey} name={line.name} stroke={line.color} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} />)}
            </LineChart>
          ) : (
            <AreaChart data={data} margin={{ top: 6, right: 4, left: -8, bottom: 0 }}>
              <ChartDecorations domain={domain} />
              {lines.map((line) => line.fill ? <Area key={line.dataKey} type="monotone" dataKey={line.dataKey} name={line.name} stroke={line.color} strokeWidth={2} fill={line.fill} fillOpacity={0.1} dot={false} isAnimationActive={false} connectNulls={false} /> : <Line key={line.dataKey} type="monotone" dataKey={line.dataKey} name={line.name} stroke={line.color} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} />)}
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
    </section>
  );
}
