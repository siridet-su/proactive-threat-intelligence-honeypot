"use client";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

interface ChartProps {
  data: { name: string; value: number; color: string }[];
  total: number;
}

export default function TargetLandscapeChart({ data, total }: ChartProps) {
  // หากไม่มีข้อมูลให้แสดงวงกลมสีเทา
  const displayData = data && total > 0 ? data : [{ name: "No Data", value: 1, color: "var(--border)" }];

  // ย่อตัวเลขให้ดูสวยงาม (เช่น 1200 -> 1.2k)
  const formattedTotal = total > 999 ? (total / 1000).toFixed(1) + 'k' : total;

  return (
    <div className="relative flex h-44 w-full items-center justify-center">
      <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none z-10">
        <span className="text-2xl font-semibold tabular-nums text-text">{formattedTotal}</span>
        <span className="mt-1 text-xs text-text-subtle">Total sessions</span>
      </div>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={displayData}
            cx="50%"
            cy="50%"
            innerRadius={54}
            outerRadius={72}
            paddingAngle={total > 0 ? 2 : 0}
            dataKey="value"
            stroke="none"
          >
            {displayData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
