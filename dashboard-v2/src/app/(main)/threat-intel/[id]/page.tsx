"use client";

import { use } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

// ข้อมูลจำลองแยกตาม ID ของ Hacker
const hackerDataMap: { [key: string]: any } = {
  "1": {
    ip: "192.168.44.122",
    trend: [
      { time: "12:44:01", APT: 15, SCRIPT: 85, BOT: 50 },
      { time: "12:44:30", APT: 25, SCRIPT: 75, BOT: 48 },
      { time: "12:45:00", APT: 60, SCRIPT: 40, BOT: 48 },
      { time: "12:45:30", APT: 85, SCRIPT: 15, BOT: 45 },
      { time: "12:46:12", APT: 95, SCRIPT: 5, BOT: 46 }, // จบที่ APT สูงสุด
    ]
  },
  "2": {
    ip: "84.21.112.5",
    trend: [
      { time: "12:44:01", APT: 10, SCRIPT: 20, BOT: 70 },
      { time: "12:44:30", APT: 12, SCRIPT: 25, BOT: 63 },
      { time: "12:45:00", APT: 15, SCRIPT: 20, BOT: 65 },
      { time: "12:45:30", APT: 10, SCRIPT: 15, BOT: 75 },
      { time: "12:46:12", APT: 8, SCRIPT: 12, BOT: 80 }, // จบที่ BOT สูงสุด
    ]
  }
};

export default function HackerProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const id = resolvedParams.id;
  
  // ดึงข้อมูลตาม ID ถ้าไม่มีให้ fallback ไปที่ ID 1
  const hackerProfile = hackerDataMap[id] || hackerDataMap["1"];
  const trendData = hackerProfile.trend;

  // 1. คำนวณผลลัพธ์จากช่วงเวลาสุดท้ายของข้อมูล
  const lastPoint = trendData[trendData.length - 1];
  const maxVal = Math.max(lastPoint.APT, lastPoint.SCRIPT, lastPoint.BOT);

  const getClassification = () => {
    if (lastPoint.APT === maxVal) return { label: "STATE-SPONSORED APT", color: "text-purple-400" };
    if (lastPoint.SCRIPT === maxVal) return { label: "SCRIPT KIDDIE", color: "text-slate-400" };
    return { label: "BOTNET ACTIVITY", color: "text-amber-400" };
  };

  const getConfidence = (val: number) => {
    if (val > 90) return { label: "HIGH CONFIDENCE", color: "bg-purple-900/50 border-purple-800 text-purple-200" };
    if (val > 60) return { label: "MEDIUM CONFIDENCE", color: "bg-amber-900/50 border-amber-800 text-amber-200" };
    return { label: "LOW CONFIDENCE", color: "bg-slate-700 border-slate-600 text-slate-300" };
  };

  const classification = getClassification();
  const confidence = getConfidence(maxVal);

  return (
    <div className="flex flex-col gap-6 pb-10">
      <div className="flex items-center gap-4">
        <h2 className="text-2xl font-bold text-white">Hacker Profile Analysis</h2>
        <span className="bg-slate-800 text-purple-400 font-mono px-3 py-1 rounded text-xs border border-purple-900/30">
          TARGET IP: {hackerProfile.ip}
        </span>
      </div>
      
      <p className="text-sm text-slate-400">Comparison of behavioral prediction models during active engagement phases.</p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/50 p-6 rounded-xl h-[400px]">
          <h3 className="text-base font-semibold text-white mb-6">Confidence Trend Analysis</h3>
          <ResponsiveContainer width="100%" height="90%">
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155" }} />
              <Legend verticalAlign="top" height={36} />
              <Line type="monotone" dataKey="APT" stroke="#a855f7" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="SCRIPT" stroke="#d946ef" strokeDasharray="5 5" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="BOT" stroke="#fbbf24" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-[#111116] border border-slate-800/50 p-6 rounded-xl">
          <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-4">Post-incident summary</p>
          <h4 className="text-slate-400 text-sm mb-2">Final Classification</h4>
          <div className={`${classification.color} text-2xl font-bold mb-4`}>{classification.label}</div>
          <span className={`px-3 py-1 rounded text-xs border ${confidence.color}`}>
            {confidence.label}
          </span>
          
          <div className="mt-8 border-t border-slate-800 pt-6">
            <p className="text-slate-400 text-xs mb-1">Session Duration</p>
            <p className="text-amber-500 font-mono text-2xl font-bold">00:02:11</p>
          </div>
        </div>
      </div>

      <div className="bg-[#0f0f13] border border-slate-800/50 rounded-xl p-6 font-mono text-xs">
        <div className="flex gap-2 mb-4">
          <div className="w-2 h-2 rounded-full bg-red-500"></div>
          <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
          <div className="w-2 h-2 rounded-full bg-green-500"></div>
          <span className="text-slate-500 ml-2">TACTICAL INTERACTION LOG</span>
        </div>
        <div className="space-y-4 text-slate-300">
          <div className="flex justify-between"><span>12:44:01 $ whoami</span><span className="text-amber-500">↳ Access Denied / Honeypot Routed</span></div>
          <div className="flex justify-between"><span>12:44:18 $ ls -la /etc/shadow</span><span className="text-amber-500">↳ Virtualizing dummy_shadow_vault... OK</span></div>
          <div className="flex justify-between"><span>12:45:03 $ cat /var/log/auth.log</span><span className="text-amber-500">↳ Returning 10.4k lines of synthetic log noise</span></div>
          <div className="flex justify-between"><span>12:46:12 $ rm -rf /sys/kernel/debug/</span><span className="text-red-500 font-bold">↳ KERNEL PANIC SIMULATED | Trapped Session Locked</span></div>
        </div>
      </div>
    </div>
  );
}