"use client";

import {
  AreaChart,
  Area,
  XAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// ข้อมูลจำลองสำหรับแสดงในกราฟ (เวลา และปริมาณการโจมตี)
const data = [
  { time: "22:00", rate: 2.5 },
  { time: "02:00", rate: 2.1 },
  { time: "06:00", rate: 6.8 },
  { time: "10:00", rate: 14.2 }, // จุดพีคตามภาพดีไซน์
  { time: "14:00", rate: 5.4 },
  { time: "18:00", rate: 9.8 },
  { time: "22:00", rate: 11.5 },
];

export default function AttackRateChart() {
  return (
    // ResponsiveContainer ช่วยให้กราฟยืดหดตามขนาดของกล่อง div ที่ครอบมันอยู่
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
        {/* ตั้งค่าการไล่สี (Gradient) จากม่วงสว่าง ไปโปร่งใส */}
        <defs>
          <linearGradient id="colorRate" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#a855f7" stopOpacity={0.6} />
            <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
          </linearGradient>
        </defs>
        
        {/* แกน X แสดงเวลาซ่อนเส้นและปรับสีตัวหนังสือให้กลืนกับพื้นหลัง */}
        <XAxis 
          dataKey="time" 
          axisLine={false} 
          tickLine={false} 
          tick={{ fill: "#64748b", fontSize: 10 }} 
          dy={10}
        />
        
        {/* ป๊อปอัปเมื่อเอาเมาส์ชี้ (Tooltip) */}
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
        
        {/* ตัวกราฟพื้นที่ type="monotone" คือทำให้เส้นโค้งมน */}
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