"use client";

import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { Gauge, History as HistoryIcon, RefreshCw, Thermometer, Wifi } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import {
  HardwareHistoryRangePicker,
  type HardwareHistoryCustomRange,
  type HardwareHistoryPreset,
  type HardwareHistoryRange,
} from "@/components/dashboard/HardwareHistoryRangePicker";
import { RegionState } from "@/components/ui/RegionState";
import { ChartWireframeSkeleton } from "@/components/ui/loaders";
import { cn } from "@/lib/utils";
import {
  isHardwareHistoryResponse,
  type HardwareHistoryMetricName,
  type HardwareHistoryPoint,
  type HardwareHistoryResponse,
} from "@/lib/dashboardTypes";

type HistoryChartRow = {
  timestampEpoch: number;
  time: string;
  cpu_min: number | null;
  cpu_avg: number | null;
  cpu_max: number | null;
  memory_min: number | null;
  memory_avg: number | null;
  memory_max: number | null;
  disk_min: number | null;
  disk_avg: number | null;
  disk_max: number | null;
  temperature_min: number | null;
  temperature_avg: number | null;
  temperature_max: number | null;
  rx_min: number | null;
  rx_avg: number | null;
  rx_max: number | null;
  tx_min: number | null;
  tx_avg: number | null;
  tx_max: number | null;
};

type HistoryView = "pressure" | "thermal" | "network";

type HistoryLine = {
  dataKey: keyof HistoryChartRow;
  metric: HardwareHistoryMetricName;
  name: string;
  color: string;
  unit: string;
  digits: number;
};

type MetricSummary = {
  latest: number;
  min: number;
  max: number;
};

const HISTORY_VIEWS: { key: HistoryView; label: string; description: string; icon: typeof Gauge; lines: HistoryLine[]; domain?: [number, number] }[] = [
  {
    key: "pressure",
    label: "Pressure",
    description: "CPU, memory, and storage",
    icon: Gauge,
    domain: [0, 100],
    lines: [
      { dataKey: "cpu_avg", metric: "cpu_percent", name: "CPU", color: "var(--chart-1)", unit: "%", digits: 1 },
      { dataKey: "memory_avg", metric: "mem_pressure_percent", name: "Memory", color: "var(--chart-6)", unit: "%", digits: 1 },
      { dataKey: "disk_avg", metric: "disk_percent", name: "Storage", color: "var(--chart-3)", unit: "%", digits: 1 },
    ],
  },
  {
    key: "thermal",
    label: "Thermal",
    description: "Temperature stability",
    icon: Thermometer,
    lines: [
      { dataKey: "temperature_avg", metric: "temperature", name: "Temperature", color: "var(--warning)", unit: "°C", digits: 1 },
    ],
  },
  {
    key: "network",
    label: "Network",
    description: "wlan0 receive and transmit",
    icon: Wifi,
    lines: [
      { dataKey: "rx_avg", metric: "net_wlan0_rx_mbps", name: "RX", color: "var(--chart-6)", unit: " Mbps", digits: 2 },
      { dataKey: "tx_avg", metric: "net_wlan0_tx_mbps", name: "TX", color: "var(--chart-1)", unit: " Mbps", digits: 2 },
    ],
  },
];

const EMPTY_SUBSCRIBE = () => () => undefined;
const CLIENT_SNAPSHOT = () => true;
const SERVER_SNAPSHOT = () => false;

function useHydrated() {
  return useSyncExternalStore(EMPTY_SUBSCRIBE, CLIENT_SNAPSHOT, SERVER_SNAPSHOT);
}

function formatHistoryTime(timestamp: string, range: HardwareHistoryRange) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return "—";
  const time = date.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit" });
  if (range === "7d" || range === "30d" || range === "custom") {
    return `${date.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
  }
  return time;
}

function metricAverage(point: HardwareHistoryPoint, name: HardwareHistoryMetricName) {
  return point.metrics[name]?.avg ?? null;
}

function roundMetric(value: number | null, fractionDigits: number) {
  return value === null ? null : Number(value.toFixed(fractionDigits));
}

function toChartRows(points: HardwareHistoryPoint[], range: HardwareHistoryRange): HistoryChartRow[] {
  return points.map((point) => ({
    timestampEpoch: Date.parse(point.timestamp),
    time: formatHistoryTime(point.timestamp, range),
    cpu_min: roundMetric(point.metrics.cpu_percent?.min ?? null, 1),
    cpu_avg: roundMetric(metricAverage(point, "cpu_percent"), 1),
    cpu_max: roundMetric(point.metrics.cpu_percent?.max ?? null, 1),
    memory_min: roundMetric(point.metrics.mem_pressure_percent?.min ?? null, 1),
    memory_avg: roundMetric(metricAverage(point, "mem_pressure_percent"), 1),
    memory_max: roundMetric(point.metrics.mem_pressure_percent?.max ?? null, 1),
    disk_min: roundMetric(point.metrics.disk_percent?.min ?? null, 1),
    disk_avg: roundMetric(metricAverage(point, "disk_percent"), 1),
    disk_max: roundMetric(point.metrics.disk_percent?.max ?? null, 1),
    temperature_min: roundMetric(point.metrics.temperature?.min ?? null, 1),
    temperature_avg: roundMetric(metricAverage(point, "temperature"), 1),
    temperature_max: roundMetric(point.metrics.temperature?.max ?? null, 1),
    rx_min: roundMetric(point.metrics.net_wlan0_rx_mbps?.min ?? null, 2),
    rx_avg: roundMetric(metricAverage(point, "net_wlan0_rx_mbps"), 2),
    rx_max: roundMetric(point.metrics.net_wlan0_rx_mbps?.max ?? null, 2),
    tx_min: roundMetric(point.metrics.net_wlan0_tx_mbps?.min ?? null, 2),
    tx_avg: roundMetric(metricAverage(point, "net_wlan0_tx_mbps"), 2),
    tx_max: roundMetric(point.metrics.net_wlan0_tx_mbps?.max ?? null, 2),
  }));
}

function summarizeMetric(points: HardwareHistoryPoint[], name: HardwareHistoryMetricName): MetricSummary | null {
  const values = points.map((point) => point.metrics[name]).filter((metric): metric is NonNullable<typeof metric> => Boolean(metric));
  if (values.length === 0) return null;
  const latest = values.at(-1)?.avg;
  if (latest === undefined) return null;
  return {
    latest,
    min: Math.min(...values.map((metric) => metric.min)),
    max: Math.max(...values.map((metric) => metric.max)),
  };
}

function formatMetricValue(value: number | null, line: HistoryLine) {
  return value === null ? "—" : `${value.toFixed(line.digits)}${line.unit}`;
}

function formatBucket(seconds: number) {
  if (seconds >= 86_400) return `${(seconds / 86_400).toFixed(seconds % 86_400 === 0 ? 0 : 1)}d`;
  if (seconds >= 3_600) return `${(seconds / 3_600).toFixed(seconds % 3_600 === 0 ? 0 : 1)}h`;
  return `${Math.max(1, Math.round(seconds / 60))}m`;
}

export function HardwareHistory() {
  const [range, setRange] = useState<HardwareHistoryRange>("24h");
  const [customRange, setCustomRange] = useState<HardwareHistoryCustomRange | null>(null);
  const [data, setData] = useState<HardwareHistoryResponse | null>(null);
  const [selectedSensorID, setSelectedSensorID] = useState<string | null>(null);
  const [view, setView] = useState<HistoryView>("pressure");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const shouldReduceMotion = useReducedMotion();
  const hydrated = useHydrated();
  const customFrom = customRange?.from.getTime() ?? null;
  const customTo = customRange?.to.getTime() ?? null;

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams();
    if (range === "custom") {
      if (customFrom === null || customTo === null) return () => controller.abort();
      params.set("range", "custom");
      params.set("from", new Date(customFrom).toISOString());
      params.set("to", new Date(customTo).toISOString());
    } else {
      params.set("range", range);
    }

    fetch(`/api/hardware/history?${params.toString()}`, { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        const payload: unknown = await response.json();
        if (!response.ok || !isHardwareHistoryResponse(payload)) throw new Error("Hardware history is unavailable");
        setData(payload);
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Hardware history is unavailable");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [customFrom, customTo, range, reloadToken]);

  const requestPresetRange = (nextRange: HardwareHistoryPreset) => {
    setLoading(true);
    setError(null);
    if (nextRange === range) setReloadToken((current) => current + 1);
    else setRange(nextRange);
  };

  const applyCustomRange = (nextRange: HardwareHistoryCustomRange) => {
    const sameRange = range === "custom" && customFrom === nextRange.from.getTime() && customTo === nextRange.to.getTime();
    setLoading(true);
    setError(null);
    setCustomRange(nextRange);
    setRange("custom");
    if (sameRange) setReloadToken((current) => current + 1);
  };

  const refreshHistory = () => {
    setLoading(true);
    setError(null);
    setReloadToken((current) => current + 1);
  };

  const selectedSeries = data?.series.find((series) => series.sensor_id === selectedSensorID) ?? data?.series[0] ?? null;
  const chartRows = useMemo(
    () => (selectedSeries ? toChartRows(selectedSeries.points, range) : []),
    [range, selectedSeries],
  );
  const activeView = HISTORY_VIEWS.find((item) => item.key === view) ?? HISTORY_VIEWS[0];
  const latestPoint = selectedSeries?.points.at(-1) ?? null;
  const controlsLoading = hydrated && Boolean(data && loading);

  return (
    <section className="ui-panel overflow-hidden p-4 sm:p-5">
      <div className="flex flex-col gap-3 border-b border-border pb-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary-subtle text-primary">
            <HistoryIcon className="h-4 w-4" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold text-text">Retained history</h2>
              <span className="rounded-full border border-border bg-surface-subtle px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.12em] text-text-subtle">1m rollups</span>
            </div>
            <p className="mt-1 text-xs text-text-muted">Historical hardware signals with averages and retained min / max range.</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 xl:justify-end">
          <HardwareHistoryRangePicker
            range={range}
            customRange={customRange}
            loading={controlsLoading}
            onPresetChange={requestPresetRange}
            onCustomApply={applyCustomRange}
          />
          <button type="button" onClick={refreshHistory} disabled={controlsLoading} className="ui-button min-h-9 px-3 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${controlsLoading ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {/* Scanning Laser Bar when loading or changing range */}
      <div className="h-0.5 w-full bg-border/40 overflow-hidden relative">
        {(loading || controlsLoading) && (
          <div
            className="absolute inset-y-0 w-56 bg-gradient-to-r from-transparent via-primary to-transparent"
            style={{
              animation: "pti-laser-scan 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
            }}
          />
        )}
      </div>

      {data && data.series.length > 1 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-text-muted">
          <span>Sensor</span>
          <select value={selectedSeries?.sensor_id ?? ""} onChange={(event) => setSelectedSensorID(event.target.value)} className="ui-field ui-select-trigger min-h-8 w-auto min-w-40 py-1 text-xs">
            {data.series.map((series) => <option key={series.sensor_id} value={series.sensor_id}>{series.sensor_id}</option>)}
          </select>
        </div>
      )}

      {loading && !data ? (
        <HistorySkeleton />
      ) : error && !data ? (
        <div className="mt-4"><RegionState kind="error" title="Hardware history unavailable" description={`${error}. Retry when the database is available.`} /></div>
      ) : !selectedSeries || selectedSeries.points.length === 0 ? (
        <div className="mt-4"><RegionState kind="empty" title="No retained history" description="New minute rollups will appear here while the hardware agent is running." /></div>
      ) : (
        <motion.div
          initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
          animate={{ opacity: 1, y: 0 }}
          transition={shouldReduceMotion ? { duration: 0 } : { duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
          className="mt-4 space-y-4"
        >
          {error && <p role="status" className="rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-xs text-warning">{error} · showing the last successful result</p>}

          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Signal view</p>
              <p className="mt-1 text-xs text-text-muted">{selectedSeries.sensor_id} · {chartRows.length} points · {formatBucket(data?.bucket_seconds ?? 60)} buckets</p>
            </div>
            <div className="grid grid-cols-3 gap-1 rounded-xl border border-border bg-surface-subtle p-1" role="tablist" aria-label="Hardware history signal view">
              {HISTORY_VIEWS.map((item) => {
                const Icon = item.icon;
                const selected = item.key === view;
                return (
                  <button
                    key={item.key}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    aria-controls={`hardware-history-${item.key}`}
                    onClick={() => setView(item.key)}
                    className={`flex min-h-9 items-center justify-center gap-1.5 rounded-lg px-2.5 text-xs transition-colors ${selected ? "bg-primary-subtle font-medium text-primary shadow-[var(--shadow-card)]" : "text-text-muted hover:bg-surface-hover hover:text-text"}`}
                    title={item.description}
                  >
                    <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div id={`hardware-history-${activeView.key}`} role="tabpanel" className="grid gap-4 lg:grid-cols-[minmax(0,1.45fr)_minmax(250px,0.55fr)] relative">
            {controlsLoading && (
              <div className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center bg-surface/40 backdrop-blur-[1.5px] rounded-xl transition-all">
                <div className="flex items-center gap-2.5 rounded-xl border border-primary-border bg-surface-raised/95 px-3.5 py-2 shadow-xl">
                  <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
                  <span className="font-mono text-xs font-semibold text-text">
                    Aggregating {range === "custom" ? "custom window" : range} rollups…
                  </span>
                </div>
              </div>
            )}
            <div className={cn("min-h-[330px] rounded-xl border border-border bg-surface-subtle p-3.5 sm:p-4 transition-opacity duration-200", controlsLoading && "opacity-40")}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-text">{activeView.label} trend</h3>
                  <p className="mt-0.5 text-xs text-text-subtle">{activeView.description} · average per bucket</p>
                </div>
                <div className="flex flex-wrap justify-end gap-x-3 gap-y-1 text-[10px] text-text-subtle">
                  {activeView.lines.map((line) => <span key={line.dataKey} className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: line.color }} />{line.name}</span>)}
                </div>
              </div>
              <div className="mt-3 h-[260px]">
                <HistoryChart data={chartRows} lines={activeView.lines} domain={activeView.domain} />
              </div>
            </div>

            <aside className="rounded-xl border border-border bg-surface-subtle p-3.5 sm:p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-text">Range snapshot</h3>
                  <p className="mt-0.5 text-xs text-text-subtle">Latest average and retained spread</p>
                </div>
                <span className="rounded-full bg-surface-hover px-2 py-1 font-mono text-[10px] tabular-nums text-text-subtle">{selectedSeries.points.length} samples</span>
              </div>

              <div className="mt-4 divide-y divide-border/70">
                {activeView.lines.map((line) => <SignalSnapshot key={line.metric} line={line} summary={summarizeMetric(selectedSeries.points, line.metric)} />)}
              </div>

              <div className="mt-4 grid grid-cols-2 gap-2 border-t border-border pt-3 text-xs">
                <div className="rounded-lg bg-surface-hover/60 p-2.5"><span className="block text-[10px] uppercase tracking-wider text-text-subtle">Bucket</span><strong className="mt-1 block font-mono text-text">{formatBucket(data?.bucket_seconds ?? 60)}</strong></div>
                <div className="rounded-lg bg-surface-hover/60 p-2.5"><span className="block text-[10px] uppercase tracking-wider text-text-subtle">Last point</span><strong className="mt-1 block truncate font-mono text-text" title={latestPoint?.timestamp}>{latestPoint ? new Date(latestPoint.timestamp).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit" }) : "—"}</strong></div>
              </div>
              <p className="mt-3 text-[11px] leading-4 text-text-subtle">Min / max use the extrema retained by each minute rollup.</p>
            </aside>
          </div>
        </motion.div>
      )}
    </section>
  );
}

function SignalSnapshot({ line, summary }: { line: HistoryLine; summary: MetricSummary | null }) {
  return (
    <div className="flex items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0">
        <p className="flex items-center gap-1.5 text-xs font-medium text-text"><span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: line.color }} />{line.name}</p>
        <p className="mt-1 text-[11px] text-text-subtle">Range {summary ? `${formatMetricValue(summary.min, line)} — ${formatMetricValue(summary.max, line)}` : "—"}</p>
      </div>
      <strong className="shrink-0 font-mono text-sm tabular-nums text-text">{summary ? formatMetricValue(summary.latest, line) : "—"}</strong>
    </div>
  );
}

function HistoryChart({ data, lines, domain }: { data: HistoryChartRow[]; lines: HistoryLine[]; domain?: [number, number] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
        <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={10} tickMargin={8} minTickGap={42} axisLine={false} tickLine={false} />
        <YAxis stroke="var(--chart-axis)" fontSize={10} domain={domain} width={38} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ stroke: "var(--border-strong)", strokeDasharray: "4 4" }} contentStyle={{ backgroundColor: "var(--surface-raised)", borderColor: "var(--border)", borderRadius: "10px", color: "var(--text)", fontSize: "11px" }} />
        {lines.map((line) => <Line key={line.dataKey} type="monotone" dataKey={line.dataKey} name={`${line.name} average`} stroke={line.color} strokeWidth={2.2} dot={false} isAnimationActive={false} connectNulls={false} />)}
      </LineChart>
    </ResponsiveContainer>
  );
}

function HistorySkeleton() {
  return (
    <div className="mt-4 space-y-4" aria-busy="true" aria-label="Loading retained history">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Signal view</p>
          <p className="mt-1 text-xs text-text-muted">Awaiting minute rollups · 60s buckets</p>
        </div>
        <div className="grid grid-cols-3 gap-1 rounded-xl border border-border bg-surface-subtle p-1">
          {HISTORY_VIEWS.map((item) => {
            const Icon = item.icon;
            const selected = item.key === "pressure";
            return (
              <div
                key={item.key}
                className={`flex min-h-9 items-center justify-center gap-1.5 rounded-lg px-2.5 text-xs ${selected ? "bg-primary-subtle font-medium text-primary shadow-[var(--shadow-card)]" : "text-text-muted/60"}`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{item.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.45fr)_minmax(250px,0.55fr)]">
        <ChartWireframeSkeleton
          title="Pressure trend"
          description="CPU, memory, and storage · average per bucket"
          lines={[
            { name: "CPU", color: "var(--chart-1)", fill: "var(--chart-1)", baselineYPercent: 92 },
            { name: "Memory", color: "var(--chart-6)", baselineYPercent: 68 },
            { name: "Storage", color: "var(--chart-3)", baselineYPercent: 48 },
          ]}
          yTicks={[100, 75, 50, 25, 0]}
          mode="line"
          className="min-h-[330px]"
          chartHeightClassName="h-[250px]"
        />

        <aside className="rounded-xl border border-border bg-surface-subtle p-3.5 sm:p-4 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-text">Range snapshot</h3>
              <p className="mt-0.5 text-xs text-text-subtle">Latest average and retained spread</p>
            </div>
            <span className="rounded-full bg-surface-hover px-2 py-1 font-mono text-[10px] tabular-nums text-text-subtle">
              Aggregating…
            </span>
          </div>

          <div className="divide-y divide-border/70">
            {[
              { name: "CPU", color: "var(--chart-1)", unit: "%" },
              { name: "Memory", color: "var(--chart-6)", unit: "%" },
              { name: "Storage", color: "var(--chart-3)", unit: "%" },
            ].map((metric) => (
              <div key={metric.name} className="flex items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: metric.color }} />
                    <span className="text-xs font-medium text-text">{metric.name}</span>
                  </div>
                  <p className="mt-1 font-mono text-[10px] text-text-subtle">min --{metric.unit} · max --{metric.unit}</p>
                </div>
                <span className="font-mono text-xs font-semibold tabular-nums text-text-subtle/80 animate-pulse">
                  --.-{metric.unit}
                </span>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-2 border-t border-border pt-3 text-xs">
            <div className="rounded-lg bg-surface-hover/60 p-2.5">
              <span className="block text-[10px] uppercase tracking-wider text-text-subtle">Bucket</span>
              <strong className="mt-1 block font-mono text-text">60s</strong>
            </div>
            <div className="rounded-lg bg-surface-hover/60 p-2.5">
              <span className="block text-[10px] uppercase tracking-wider text-text-subtle">Last point</span>
              <strong className="mt-1 block truncate font-mono text-text-subtle/80">Awaiting…</strong>
            </div>
          </div>
          <p className="text-[11px] text-text-subtle">
            Reading minute-level rollups from hardware_metrics_1m.
          </p>
        </aside>
      </div>
    </div>
  );
}
