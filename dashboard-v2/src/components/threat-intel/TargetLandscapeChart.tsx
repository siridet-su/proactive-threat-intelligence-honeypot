"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

export interface LandscapeDatum {
  name: string;
  value: number;
  color: string;
}

export default function TargetLandscapeChart({
  data,
  totalLabel,
}: {
  data: LandscapeDatum[];
  totalLabel: string;
}) {
  if (!data.length) {
    return (
      <div className="h-48 flex items-center justify-center text-center text-[11px] text-slate-500">
        No verified session classification data.
      </div>
    );
  }

  return (
    <div className="relative w-full h-48 flex items-center justify-center">
      <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none z-10">
        <span className="text-2xl font-bold text-white">{totalLabel}</span>
        <span className="text-[9px] text-slate-400 tracking-wider">SHOWN SESSIONS</span>
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
