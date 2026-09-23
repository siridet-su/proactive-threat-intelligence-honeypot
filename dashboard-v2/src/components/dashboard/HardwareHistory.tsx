"use client";

import { useEffect, useMemo, useState } from "react";
import { History, RefreshCw } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import {
  HardwareHistoryRangePicker,
  type HardwareHistoryCustomRange,
  type HardwareHistoryPreset,
  type HardwareHistoryRange,
} from "@/components/dashboard/HardwareHistoryRangePicker";
import { RegionState } from "@/components/ui/RegionState";
import {
  isHardwareHistoryResponse,
  type HardwareHistoryMetricName,
  type HardwareHistoryPoint,
  type HardwareHistoryResponse,
} from "@/lib/dashboardTypes";

type HistoryChartRow = {
  timestampEpoch: number;
  time: string;
  cpu_avg: number | null;
  memory_avg: number | null;
  disk_avg: number | null;
  temperature_avg: number | null;
  rx_avg: number | null;
  tx_avg: number | null;
};

type HistoryLine = {
  dataKey: keyof HistoryChartRow;
  name: string;
  color: string;
};

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
  const metric = point.metrics[name];
  return metric ? metric.avg : null;
}

function roundMetric(value: number | null, fractionDigits: number) {
  return value === null ? null : Number(value.toFixed(fractionDigits));
}

function toChartRows(points: HardwareHistoryPoint[], range: HardwareHistoryRange): HistoryChartRow[] {
  return points.map((point) => ({
    timestampEpoch: Date.parse(point.timestamp),
    time: formatHistoryTime(point.timestamp, range),
    cpu_avg: roundMetric(metricAverage(point, "cpu_percent"), 1),
    memory_avg: roundMetric(metricAverage(point, "mem_pressure_percent"), 1),
    disk_avg: roundMetric(metricAverage(point, "disk_percent"), 1),
    temperature_avg: roundMetric(metricAverage(point, "temperature"), 1),
    rx_avg: roundMetric(metricAverage(point, "net_wlan0_rx_mbps"), 2),
    tx_avg: roundMetric(metricAverage(point, "net_wlan0_tx_mbps"), 2),
  }));
}

export function HardwareHistory() {
  const [range, setRange] = useState<HardwareHistoryRange>("24h");
  const [customRange, setCustomRange] = useState<HardwareHistoryCustomRange | null>(null);
  const [data, setData] = useState<HardwareHistoryResponse | null>(null);
  const [selectedSensorID, setSelectedSensorID] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
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
        if (!response.ok || !isHardwareHistoryResponse(payload)) {
          throw new Error("Hardware history is unavailable");
        }
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

  return (
    <section className="flex flex-col gap-4 rounded-lg border border-border bg-surface p-4 shadow-[var(--shadow-card)]">
      <div className="flex flex-col gap-3 border-b border-border pb-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 className="text-base font-semibold">Hardware history</h2>
          </div>
          <p className="mt-1 text-xs text-text-muted">
            Minute rollups from hardware_metrics_1m · charts show averages; min/max are retained per point
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <HardwareHistoryRangePicker
            range={range}
            customRange={customRange}
            loading={loading}
            onPresetChange={requestPresetRange}
            onCustomApply={applyCustomRange}
          />
          <button
            type="button"
            onClick={refreshHistory}
            disabled={loading}
            className="ui-button min-h-9 px-3 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {data && data.series.length > 1 && (
        <label className="flex items-center gap-2 text-xs text-text-muted">
          Sensor
          <select
            value={selectedSeries?.sensor_id ?? ""}
            onChange={(event) => setSelectedSensorID(event.target.value)}
            className="ui-field ui-select-trigger min-h-8 py-1 text-xs"
          >
            {data.series.map((series) => <option key={series.sensor_id} value={series.sensor_id}>{series.sensor_id}</option>)}
          </select>
        </label>
      )}

      {loading && !data ? (
        <RegionState kind="loading" title="Loading hardware history" description="Reading retained minute rollups." />
      ) : error && !data ? (
        <RegionState kind="error" title="Hardware history unavailable" description={`${error}. Retry when the database is available.`} />
      ) : !selectedSeries || selectedSeries.points.length === 0 ? (
        <RegionState kind="empty" title="No hardware history" description="New minute rollups will appear here while the hardware agent is running." />
      ) : (
        <>
          {error && <p role="status" className="text-xs text-warning">{error} · showing the last successful result</p>}
          <p className="text-xs text-text-subtle">
            {selectedSeries.sensor_id} · {chartRows.length} point{chartRows.length === 1 ? "" : "s"} · {(data?.bucket_seconds ?? 0) >= 3600 ? `${(data?.bucket_seconds ?? 0) / 3600}h` : `${(data?.bucket_seconds ?? 0) / 60}m`} buckets
          </p>
          <div className="grid min-h-[240px] grid-cols-1 gap-4 xl:grid-cols-2">
            <HistoryChart title="CPU / memory pressure" description="Average percentage" data={chartRows} lines={[{ dataKey: "cpu_avg", name: "CPU (%)", color: "var(--chart-1)" }, { dataKey: "memory_avg", name: "Memory pressure (%)", color: "var(--chart-6)" }]} domain={[0, 100]} />
            <HistoryChart title="Storage" description="Average disk usage" data={chartRows} lines={[{ dataKey: "disk_avg", name: "Disk (%)", color: "var(--chart-3)" }]} domain={[0, 100]} />
            <HistoryChart title="Temperature" description="Average temperature in °C" data={chartRows} lines={[{ dataKey: "temperature_avg", name: "Temperature (°C)", color: "var(--warning)" }]} />
            <HistoryChart title="wlan0 throughput" description="Average Mbps" data={chartRows} lines={[{ dataKey: "rx_avg", name: "RX (Mbps)", color: "var(--chart-6)" }, { dataKey: "tx_avg", name: "TX (Mbps)", color: "var(--chart-1)" }]} />
          </div>
        </>
      )}
    </section>
  );
}

function HistoryChart({ title, description, data, lines, domain }: { title: string; description: string; data: HistoryChartRow[]; lines: HistoryLine[]; domain?: [number, number] }) {
  return (
    <section className="flex min-h-[240px] flex-col rounded-lg border border-border bg-surface-subtle p-4" aria-label={title}>
      <div>
        <h3 className="text-xs font-medium text-text-muted">{title}</h3>
        <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-text-subtle">
          <span>{description}</span>
          {lines.map((line) => <span key={line.dataKey} className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ backgroundColor: line.color }} />{line.name}</span>)}
        </div>
      </div>
      <div className="mt-3 min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 4, left: 2, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
            <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} />
            <YAxis stroke="var(--chart-axis)" fontSize={12} domain={domain} width={42} />
            <Tooltip contentStyle={{ backgroundColor: "var(--surface-raised)", borderColor: "var(--border)", color: "var(--text)", fontSize: "12px" }} />
            {lines.map((line) => <Line key={line.dataKey} type="monotone" dataKey={line.dataKey} name={line.name} stroke={line.color} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls={false} />)}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
