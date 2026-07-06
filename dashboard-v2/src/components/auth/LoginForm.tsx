"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginForm() {
  const [operatorId, setOperatorId] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleAuthenticate = (e: React.FormEvent) => {
  e.preventDefault();
  
  // ตรวจสอบข้อมูลม็อกอัพ
  if (operatorId === "OP_4725" && accessKey === "password098") {
    setError("");
    
    // เอาคอมเมนต์ออกเพื่อให้คำสั่งทำงาน (และสามารถลบหรือปิดตัว alert ออกได้เลยเพื่อความลื่นไหล)
    router.push("/dashboard"); 
    
  } else {
    setError("ACCESS DENIED: Invalid Operator ID or Access Key.");
  }
};

  return (
    <div className="relative w-full max-w-md p-[1px] rounded-lg bg-gradient-to-b from-purple-500/30 to-transparent">
      <div className="bg-[#0a0a0c] p-10 rounded-lg shadow-2xl flex flex-col items-center border border-purple-900/30">
        
        {/* Shield Icon */}
        <div className="mb-4 text-purple-400">
          <svg className="w-8 h-8" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-1.998A11.954 11.954 0 0110 1.944z" clipRule="evenodd" />
          </svg>
        </div>

        {/* Title */}
        <h2 className="text-xl text-white font-semibold tracking-[0.2em] mb-1">ACCESS CONTROL</h2>
        <p className="text-[10px] text-slate-500 font-mono mb-8 tracking-widest">SECURE TERMINAL NODE: 0x8F-B22</p>

        <form onSubmit={handleAuthenticate} className="w-full flex flex-col gap-5">
          
          {/* Operator ID Input */}
          <div>
            <div className="flex justify-between mb-2">
              <label className="text-xs text-slate-400 font-mono tracking-wider">OPERATOR ID</label>
              <span className="text-[10px] text-slate-600 font-mono">REQUIRED</span>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
              </div>
              <input 
                type="text" 
                placeholder="OP_XXXX"
                value={operatorId}
                onChange={(e) => setOperatorId(e.target.value)}
                className="w-full bg-[#111116] border border-slate-800 text-slate-300 text-sm rounded-md focus:ring-purple-500 focus:border-purple-500 block pl-10 p-2.5 font-mono outline-none transition-colors"
                required
              />
            </div>
          </div>

          {/* Access Key Input */}
          <div>
             <div className="flex justify-between mb-2">
              <label className="text-xs text-slate-400 font-mono tracking-wider">ACCESS KEY</label>
              <span className="text-[10px] text-slate-600 font-mono">ENCRYPTED</span>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
              </div>
              <input 
                type="password" 
                placeholder="••••••••••••"
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                className="w-full bg-[#111116] border border-slate-800 text-slate-300 text-sm rounded-md focus:ring-purple-500 focus:border-purple-500 block pl-10 p-2.5 font-mono outline-none transition-colors"
                required
              />
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <p className="text-red-500 text-xs font-mono text-center mt-1 animate-pulse">{error}</p>
          )}

          {/* Submit Button */}
          <button 
            type="submit" 
            className="mt-4 w-full bg-purple-700 hover:bg-purple-600 text-white font-medium rounded-md text-sm px-5 py-3 text-center flex justify-center items-center gap-2 transition-all shadow-[0_0_15px_rgba(126,34,206,0.3)] hover:shadow-[0_0_25px_rgba(126,34,206,0.5)] font-mono tracking-wider"
          >
            AUTHENTICATE
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </button>

        </form>

        {/* Footer Warning */}
        <div className="mt-8 text-center flex flex-col gap-2">
          <a href="#" className="text-[10px] text-slate-400 font-mono hover:text-purple-400 transition-colors">FORGOT ACCESS KEY?</a>
          <p className="text-[9px] text-slate-600 font-mono mt-4 max-w-[250px] leading-relaxed">
            WARNING: UNAUTHORIZED ACCESS ATTEMPTS ARE MONITORED AND LOGGED. FEDERAL PROSECUTION MAY APPLY.
          </p>
        </div>

      </div>
    </div>
  );
}