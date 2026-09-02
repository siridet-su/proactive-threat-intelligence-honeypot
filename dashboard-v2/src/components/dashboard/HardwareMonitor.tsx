"use client";

import { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, CartesianGrid } from "recharts";
import { Cpu, MemoryStick, HardDrive, Thermometer, Wifi } from "lucide-react";

export function HardwareMonitor() {
  const [metrics, setMetrics] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await fetch("/api/hardware");
        if (res.ok) {
          const data = await res.json();
          // Format timestamps for chart
          const formatted = data.map((d: any) => {
            const date = new Date(d.timestamp);
            return {
              ...d,
              time: `${date.getHours()}:${date.getMinutes().toString().padStart(2, "0")}:${date.getSeconds().toString().padStart(2, "0")}`,
            };
          });
          setMetrics(formatted);
        }
      } catch (err) {
        console.error("Fetch metrics error:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    // Poll every 10 seconds (matches hardware-agent interval)
    const interval = setInterval(fetchMetrics, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && metrics.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-slate-500 font-mono text-xs animate-pulse">
        CONNECTING TO HARDWARE SENSORS...
      </div>
    );
  }

  const latest = metrics[metrics.length - 1] || { cpu_percent: 0, mem_percent: 0, disk_percent: 0, temperature: 0 };

  return (
    <div className="flex flex-col gap-6 h-full">
      {/* Top Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {/* CPU */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex items-center gap-3">
          <div className="p-2 bg-purple-500/20 text-purple-400 rounded-md"><Cpu size={16} /></div>
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">CPU Usage</div>
            <div className="text-lg font-mono text-white">{Number(latest.cpu_percent || 0).toFixed(1)}%</div>
          </div>
        </div>
        {/* RAM */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex items-center gap-3">
          <div className="p-2 bg-emerald-500/20 text-emerald-400 rounded-md"><MemoryStick size={16} /></div>
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Memory</div>
            <div className="text-lg font-mono text-white">{Number(latest.mem_percent || 0).toFixed(1)}%</div>
          </div>
        </div>
        {/* Disk */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex items-center gap-3">
          <div className="p-2 bg-blue-500/20 text-blue-400 rounded-md"><HardDrive size={16} /></div>
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Storage</div>
            <div className="text-lg font-mono text-white">{Number(latest.disk_percent || 0).toFixed(1)}%</div>
          </div>
        </div>
        {/* Temp */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex items-center gap-3">
          <div className="p-2 bg-red-500/20 text-red-400 rounded-md"><Thermometer size={16} /></div>
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Temperature</div>
            <div className="text-lg font-mono text-white">{Number(latest.temperature || 0).toFixed(1)}°C</div>
          </div>
        </div>
        {/* Network wlan0 */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex items-center gap-3 col-span-2 lg:col-span-1">
          <div className="p-2 bg-cyan-500/20 text-cyan-400 rounded-md"><Wifi size={16} /></div>
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">wlan0 (RX/TX)</div>
            <div className="text-lg font-mono text-white">
              {Number(latest.net_wlan0_rx_mbps || 0).toFixed(2)} / {Number(latest.net_wlan0_tx_mbps || 0).toFixed(2)} <span className="text-[10px] text-slate-500">Mbps</span>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 flex-1 min-h-[200px]">
        {/* CPU Chart */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex flex-col">
          <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 font-semibold">CPU History</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#52525b" fontSize={10} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', fontSize: '12px' }} />
                <Area type="monotone" dataKey="cpu_percent" stroke="#a855f7" strokeWidth={2} fillOpacity={1} fill="url(#colorCpu)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Temp Chart */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex flex-col">
          <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 font-semibold">Thermal History</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTemp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f87171" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f87171" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#52525b" fontSize={10} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', fontSize: '12px' }} />
                <Area type="monotone" dataKey="temperature" stroke="#f87171" strokeWidth={2} fillOpacity={1} fill="url(#colorTemp)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Network Chart */}
        <div className="bg-[#18181b] border border-slate-700/50 rounded-lg p-3 flex flex-col">
          <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-2 font-semibold">wlan0 Throughput</div>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#52525b" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', fontSize: '12px' }} />
                <Line type="monotone" dataKey="net_wlan0_rx_mbps" name="RX (Mbps)" stroke="#06b6d4" strokeWidth={2} dot={false} isAnimationActive={false} />
                <Line type="monotone" dataKey="net_wlan0_tx_mbps" name="TX (Mbps)" stroke="#3b82f6" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
