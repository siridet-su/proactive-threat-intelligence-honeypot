"use client";

import {
  AreaChart,
  Area,
  XAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export interface ActivityPoint {
  time: string;
  rate: number;
}

export default function AttackRateChart({ data }: { data: ActivityPoint[] }) {
  if (!data.length) {
    return (
      <div className="h-full flex items-center justify-center text-center text-[11px] text-slate-500">
        No session observations in the selected 24-hour window.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="colorRate" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#a855f7" stopOpacity={0.6} />
            <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
          </linearGradient>
        </defs>
        
        <XAxis 
          dataKey="time" 
          axisLine={false} 
          tickLine={false} 
          tick={{ fill: "#64748b", fontSize: 10 }} 
          dy={10}
        />
        
        <Tooltip
          contentStyle={{
            backgroundColor: "#111116",
            borderColor: "#334155",
            borderRadius: "8px",
            color: "#e2e8f0",
            fontSize: "12px",
          }}
          itemStyle={{ color: "#a855f7" }}
        />
        
        <Area
          type="monotone"
          dataKey="rate"
          stroke="#a855f7"
          strokeWidth={3}
          fillOpacity={1}
          fill="url(#colorRate)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
