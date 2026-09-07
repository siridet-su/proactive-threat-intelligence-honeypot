"use client";

import { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, CartesianGrid } from "recharts";
import { Cpu, MemoryStick, HardDrive, Thermometer, Wifi } from "lucide-react";
import {
  formatHardwareMetric,
  isHardwareTelemetry,
  parseHardwareStreamMessage,
} from "@/lib/dashboardTypes";
import type { HardwareChartRecord, HardwareTelemetry } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";

export function HardwareMonitor() {
  const [metrics, setMetrics] = useState<HardwareChartRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);

  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    let reconnectTimer: number | null = null;
    let fallbackTimer: number | null = null;
    let hasSnapshot = false;

    const replaceMetrics = (incoming: HardwareTelemetry[]) => {
      hasSnapshot = true;
      setMetrics(incoming.filter(isHardwareTelemetry).map(formatHardwareMetric).slice(-30));
      setFetchFailed(false);
      setLoading(false);
    };

    const appendMetric = (incoming: HardwareTelemetry) => {
      hasSnapshot = true;
      setMetrics((current) => [...current, formatHardwareMetric(incoming)].slice(-30));
      setFetchFailed(false);
      setLoading(false);
    };

    const fetchSnapshot = async () => {
      try {
        const res = await fetch("/api/hardware");
        if (!res.ok) throw new Error("Hardware request failed");
        const data: unknown = await res.json();
        if (!Array.isArray(data)) throw new Error("Hardware response unavailable");
        replaceMetrics(data.filter(isHardwareTelemetry));
      } catch {
        if (!hasSnapshot) setFetchFailed(true);
      } finally {
        setLoading(false);
      }
    };

    const stopFallback = () => {
      if (fallbackTimer === null) return;
      window.clearInterval(fallbackTimer);
      fallbackTimer = null;
    };

    const startFallback = () => {
      if (fallbackTimer !== null) return;
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
      const connection = new EventSource("/api/hardware/stream");
      source = connection;

      connection.onmessage = (event) => {
        try {
          const message = parseHardwareStreamMessage(JSON.parse(event.data));
          if (!message) return;
          if (message.type === "initial") replaceMetrics(message.data);
          else appendMetric(message.data);
        } catch {
          // Retain the last valid telemetry point when one SSE message is malformed.
        }
      };

      connection.onopen = () => {
        if (disposed) return;
        stopFallback();
      };

      connection.onerror = () => {
        if (disposed || source !== connection) return;
        connection.close();
        source = null;
        if (!hasSnapshot) {
          setFetchFailed(true);
          setLoading(false);
        }
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

  if (loading && metrics.length === 0) {
    return (
      <div className="flex h-full flex-col gap-5" aria-busy="true" aria-label="Loading hardware telemetry">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          {Array.from({ length: 5 }, (_, index) => <div key={index} className="rounded-lg border border-border bg-surface-subtle p-3"><div className="flex items-center gap-3"><div className="ui-skeleton h-8 w-8" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-3 w-16" /><div className="ui-skeleton h-5 w-20" /></div></div></div>)}
        </div>
        <div className="grid min-h-[200px] flex-1 grid-cols-1 gap-4 lg:grid-cols-3">
          {Array.from({ length: 3 }, (_, index) => <div key={index} className="flex flex-col rounded-lg border border-border bg-surface-subtle p-4"><div className="ui-skeleton mb-4 h-3 w-24" /><div className="ui-skeleton flex-1" /></div>)}
        </div>
      </div>
    );
  }

  if (metrics.length === 0) {
    return <RegionState kind={fetchFailed ? "error" : "empty"} title={fetchFailed ? "Hardware telemetry unavailable" : "No hardware telemetry"} description={fetchFailed ? "The hardware service could not be reached. The next automatic refresh will try again." : "No telemetry points were returned in the last successful response."} />;
  }

  const latest = metrics[metrics.length - 1] || { cpu_percent: 0, mem_percent: 0, disk_percent: 0, temperature: 0 };

  return (
    <div className="flex h-full flex-col gap-5">
      {/* Top Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {/* CPU */}
        <div className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3">
          <div className="flex items-center gap-3"><div className="rounded-md bg-primary-subtle p-2 text-primary"><Cpu size={16} /></div>
          <div>
            <div className="text-xs font-medium text-text-muted">CPU usage</div>
            <div className="font-mono text-lg text-text">{Number(latest.cpu_percent || 0).toFixed(1)}%</div>
          </div>
          </div>
        </div>
        {/* RAM */}
        <div className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3">
          <div className="flex items-center gap-3"><div className="rounded-md bg-success-subtle p-2 text-success"><MemoryStick size={16} /></div>
          <div>
            <div className="text-xs font-medium text-text-muted">Memory</div><div className="font-mono text-lg text-text">{Number(latest.mem_percent || 0).toFixed(1)}%</div>
          </div>
          </div>
        </div>
        {/* Disk */}
        <div className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3">
          <div className="flex items-center gap-3"><div className="rounded-md bg-info-subtle p-2 text-info"><HardDrive size={16} /></div>
          <div>
            <div className="text-xs font-medium text-text-muted">Storage</div><div className="font-mono text-lg text-text">{Number(latest.disk_percent || 0).toFixed(1)}%</div>
          </div>
          </div>
        </div>
        {/* Temp */}
        <div className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3">
          <div className="flex items-center gap-3"><div className="rounded-md bg-danger-subtle p-2 text-danger"><Thermometer size={16} /></div>
          <div>
            <div className="text-xs font-medium text-text-muted">Temperature</div><div className="font-mono text-lg text-text">{Number(latest.temperature || 0).toFixed(1)}°C</div>
          </div>
          </div>
        </div>
        {/* Network wlan0 */}
        <div className="ui-panel-interactive col-span-2 rounded-lg border border-border bg-surface-subtle p-3 lg:col-span-1">
          <div className="flex items-center gap-3"><div className="rounded-md bg-info-subtle p-2 text-info"><Wifi size={16} /></div>
          <div>
            <div className="text-xs font-medium text-text-muted">wlan0 (RX/TX)</div>
            <div className="font-mono text-lg text-text">
              {Number(latest.net_wlan0_rx_mbps || 0).toFixed(2)} / {Number(latest.net_wlan0_tx_mbps || 0).toFixed(2)} <span className="text-xs text-text-subtle">Mbps</span>
            </div>
          </div>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid min-h-[200px] flex-1 grid-cols-1 gap-4 lg:grid-cols-3">
        {/* CPU Chart */}
        <div className="flex flex-col rounded-lg border border-border bg-surface-subtle p-4">
          <div className="mb-2 text-xs font-medium text-text-muted">CPU history</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="var(--chart-axis)" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--surface-raised)', borderColor: 'var(--border)', color: 'var(--text)', fontSize: '12px' }} />
                <Area type="monotone" dataKey="cpu_percent" stroke="var(--chart-1)" strokeWidth={2} fillOpacity={1} fill="var(--primary-subtle)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Temp Chart */}
        <div className="flex flex-col rounded-lg border border-border bg-surface-subtle p-4">
          <div className="mb-2 text-xs font-medium text-text-muted">Thermal history</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="var(--chart-axis)" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--surface-raised)', borderColor: 'var(--border)', color: 'var(--text)', fontSize: '12px' }} />
                <Area type="monotone" dataKey="temperature" stroke="var(--danger)" strokeWidth={2} fillOpacity={1} fill="var(--danger-subtle)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Network Chart */}
        <div className="flex flex-col rounded-lg border border-border bg-surface-subtle p-4">
          <div className="mb-2 text-xs font-medium text-text-muted">wlan0 throughput</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="var(--chart-axis)" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--surface-raised)', borderColor: 'var(--border)', color: 'var(--text)', fontSize: '12px' }} />
                <Line type="monotone" dataKey="net_wlan0_rx_mbps" name="RX (Mbps)" stroke="var(--chart-6)" strokeWidth={2} dot={false} isAnimationActive={false} />
                <Line type="monotone" dataKey="net_wlan0_tx_mbps" name="TX (Mbps)" stroke="var(--chart-1)" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
