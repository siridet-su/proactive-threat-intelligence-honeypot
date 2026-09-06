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
      <div className="h-full flex items-center justify-center text-center text-xs text-text-subtle">
        No session observations in the selected 24-hour window.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
        <XAxis
          dataKey="time"
          axisLine={false}
          tickLine={false}
          tick={{ fill: "var(--chart-axis)", fontSize: 12 }}
          dy={10}
        />

        <Tooltip
          contentStyle={{
            backgroundColor: "var(--surface-raised)",
            borderColor: "var(--border)",
            borderRadius: "8px",
            color: "var(--text)",
            fontSize: "12px",
          }}
          itemStyle={{ color: "var(--chart-1)" }}
        />

        <Area
          type="monotone"
          dataKey="rate"
          stroke="var(--chart-1)"
          strokeWidth={3}
          fillOpacity={0.12}
          fill="var(--chart-1)"
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
