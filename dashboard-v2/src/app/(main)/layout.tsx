"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ShieldCheck, LayoutDashboard, Brain, Search, Clock, LogOut, ArrowLeft, Bug } from "lucide-react";
import { useEffect, useState } from "react";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter(); // เพิ่ม useRouter สำหรับคุมการเปลี่ยนหน้า
  const [time, setTime] = useState("");

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString('en-US', { hour12: false }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const isDashboard = pathname === "/dashboard";
  const isThreatIntel = pathname === "/threat-intel"; // เช็คหน้า Threat Intel หน้าหลัก

  // ฟังก์ชัน: จัดการเมื่อกดปุ่ม Log Out
  const handleLogout = () => {
    if (window.confirm("คุณต้องการออกจากระบบและกลับสู่หน้าแรกใช่หรือไม่?")) {
      router.push("/");
    }
  };

  // ฟังก์ชัน: จัดการเมื่อกดปุ่ม ย้อนกลับ (Back)
  const handleBack = () => {
    // ถ้าอยู่หน้า Dashboard หลัก การกด Back ถือว่าเป็นการพยายามออกจากระบบ
    if (pathname === "/dashboard") {
      if (window.confirm("การย้อนกลับจากหน้านี้จะเป็นการออกจากระบบ คุณยืนยันหรือไม่?")) {
        router.push("/");
      }
    } else {
      // หน้าอื่นๆ เช่น Threat Intel Detail ให้ย้อนกลับตามประวัติเบราว์เซอร์ปกติ
      router.back();
    }
  };

  return (
    <div className="flex h-screen bg-[#0a0a0c] text-white overflow-hidden font-mono selection:bg-purple-500/30">
      
      {/* ---------------- Sidebar ---------------- */}
      <aside className="w-64 bg-[#111116] border-r border-slate-800/50 flex flex-col z-50 shrink-0">
         <div className="h-20 flex items-center px-6 border-b border-slate-800/50">
            <div className="w-8 h-8 rounded-lg bg-purple-900/30 border border-purple-500/30 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-4 h-4 text-purple-400" />
            </div>
            <span className="ml-3 font-bold text-lg text-purple-200 tracking-wider">PTI-Honeypot</span>
         </div>

         <nav className="flex-1 px-4 py-6 overflow-y-auto space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500 px-2 mb-4">Vigilance Protocol</div>
            
            <Link href="/dashboard" className={`flex items-center gap-3 px-4 py-3 rounded-md transition-colors ${
                pathname === "/dashboard" ? 'bg-purple-900/20 text-purple-300 border-l-2 border-purple-500' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border-l-2 border-transparent'
            }`}>
                <LayoutDashboard className="w-[18px] h-[18px]" /> 
                <span className="text-sm">Dashboard</span>
            </Link>

            <Link href="/threat-intel" className={`flex items-center gap-3 px-4 py-3 rounded-md transition-colors ${
                pathname.includes("/threat-intel") ? 'bg-purple-900/20 text-purple-300 border-l-2 border-purple-500' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border-l-2 border-transparent'
            }`}>
                <Brain className="w-[18px] h-[18px]" /> 
                <span className="text-sm">Threat Intel</span>
            </Link>

            <Link href="/malware-vault" className={`flex items-center gap-3 px-4 py-3 rounded-md transition-colors ${
                pathname.includes("/malware-vault") ? 'bg-red-900/20 text-red-400 border-l-2 border-red-500' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border-l-2 border-transparent'
            }`}>
                <Bug className="w-[18px] h-[18px]" /> 
                <span className="text-sm">Malware Vault</span>
            </Link>
         </nav>

         <div className="p-6 border-t border-slate-800/50">
            <div className="flex items-center gap-3 mb-6">
               <div className="w-8 h-8 rounded-full bg-purple-600 flex items-center justify-center text-xs text-white">SA</div>
               <div>
                  <p className="text-sm font-semibold text-slate-200">Security Analyst</p>
                  <p className="text-[10px] text-slate-500">LVL-4 ACCESS</p>
               </div>
            </div>
            
            {/* เพิ่มปุ่ม Log out */}
            <button 
              onClick={handleLogout}
              className="mt-2 w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-900/20 hover:bg-red-900/40 text-red-400 border border-red-900/30 rounded-lg text-sm transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Log out</span>
            </button>
         </div>
      </aside>

      {/* ---------------- Main Content ---------------- */}
      <main className="flex-1 flex flex-col min-w-0 bg-[#0a0a0c]">
        {/* Topbar */}
        <header className="h-20 bg-[#0a0a0c]/90 backdrop-blur-xl border-b border-slate-800/50 flex items-center justify-between px-8 shrink-0">
            <div className="flex items-center text-sm gap-4 text-slate-400">
                {/* เพิ่มปุ่ม ย้อนกลับ (Back Button) */}
                <button 
                  onClick={handleBack} 
                  className="p-2 bg-slate-900/50 hover:bg-slate-800 border border-slate-800 rounded-full transition-colors text-slate-400 hover:text-white"
                  title="Go Back"
                >
                    <ArrowLeft className="w-4 h-4" />
                </button>

                <span className="text-white font-medium text-lg">
                  {pathname.includes('/malware-vault') ? 'Malware Vault' : pathname.includes('/threat-intel/') ? 'Hacker Profile Analysis' : isThreatIntel ? 'Threat Intelligence' : 'System Overview'}
                </span>
            </div>

            <div className="flex items-center gap-6">
                <div className="relative">
                    <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                    <input type="text" placeholder="Scan nodes..." className="bg-[#111116] border border-slate-800 rounded-full pl-10 pr-4 py-2 text-sm text-slate-300 w-72 focus:outline-none focus:border-purple-500 transition-all font-sans" />
                </div>
                <div className="w-px h-6 bg-slate-800"></div>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                    <Clock className="w-4 h-4" />
                    <span>{time || "00:00:00"}</span>
                </div>
            </div>
        </header>
        
        {/* กำหนด padding (p-6, lg:p-8) และความกว้างสูงสุด (max-w-[1600px]) ไว้ที่นี่เลย */}
        <div className="flex-1 overflow-y-auto p-6 lg:p-8">
            <div className="max-w-[1600px] mx-auto w-full h-full">
                {children}
            </div>
        </div>
      </main>
    </div>
  );
}