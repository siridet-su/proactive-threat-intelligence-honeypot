import Link from "next/link";

export default function Navbar() {
  return (
    <nav className="w-full flex items-center justify-between py-6 px-8 absolute top-0 left-0 right-0 z-50">
      {/* Logo */}
      <div className="text-xl font-bold tracking-wider text-purple-200">
        PTI-Honeypot
      </div>

      {/* Status & Icons */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 border border-slate-700 bg-slate-900/50 px-4 py-1.5 rounded-full text-xs text-slate-300 font-mono tracking-widest">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          SYSTEM STATUS
        </div>
        <button className="text-slate-400 hover:text-white transition">
          {/* ใช้ไอคอนจำลอง หรือใส่ Heroicons ที่นี่ */}
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
        </button>
      </div>
    </nav>
  );
}