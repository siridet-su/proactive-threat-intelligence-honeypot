"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

const data = [
  { name: "Bot", value: 45, color: "#d946ef" }, // สีชมพูอมม่วง
  { name: "APT", value: 25, color: "#a855f7" }, // สีม่วง
  { name: "Script", value: 20, color: "#64748b" }, // สีเทา
  { name: "Other", value: 10, color: "#d97706" }, // สีส้ม
];

export default function TargetLandscapeChart() {
  return (
    <div className="relative w-full h-48 flex items-center justify-center">
      {/* ข้อความตรงกลางโดนัท */}
      <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none z-10">
        <span className="text-2xl font-bold text-white">1.2k</span>
        <span className="text-[9px] text-slate-400 tracking-wider">DAILY PEAKS</span>
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