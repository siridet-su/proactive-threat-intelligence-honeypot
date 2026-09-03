"use client";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

interface ChartProps {
  data: { name: string; value: number; color: string }[];
  total: number;
}

export default function TargetLandscapeChart({ data, total }: ChartProps) {
  // หากไม่มีข้อมูลให้แสดงวงกลมสีเทา
  const displayData = data && total > 0 ? data : [{ name: "No Data", value: 1, color: "#27272a" }];
  
  // ย่อตัวเลขให้ดูสวยงาม (เช่น 1200 -> 1.2k)
  const formattedTotal = total > 999 ? (total / 1000).toFixed(1) + 'k' : total;

  return (
    <div className="relative w-full h-48 flex items-center justify-center">
      <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none z-10">
        <span className="text-2xl font-bold text-white">{formattedTotal}</span>
        <span className="text-[9px] text-slate-400 tracking-wider">TOTAL SESSIONS</span>
      </div>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={displayData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
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