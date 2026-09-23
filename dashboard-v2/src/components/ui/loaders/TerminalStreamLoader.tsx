"use client";

import { Terminal, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

interface TerminalStreamLoaderProps {
  title?: string;
  subtitle?: string;
  className?: string;
  lines?: number;
}

export function TerminalStreamLoader({
  title = "Decrypting Incursion Command Stream...",
  subtitle = "Intercepted raw tty packets are being parsed & classified against MITRE ATT&CK",
  className,
  lines = 4,
}: TerminalStreamLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "rounded-xl border border-slate-800 bg-[#0B1220] shadow-xl overflow-hidden font-mono text-xs select-none",
        className
      )}
    >
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#141d2d] px-4 py-2.5">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5" aria-hidden="true">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <span className="text-[11px] text-slate-400 font-semibold flex items-center gap-1.5">
            <Terminal className="h-3 w-3 text-primary" />
            attacker@honeypot:~#
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-primary animate-ping" />
          <span className="text-[10px] text-primary font-bold tracking-wider uppercase">
            LIVE DECOY BUFFER
          </span>
        </div>
      </div>

      {/* Terminal Body */}
      <div className="p-4 space-y-3">
        {/* Decrypting Status Banner */}
        <div className="flex items-center justify-between rounded border border-primary/20 bg-primary/10 px-3 py-2 text-primary text-[11px]">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-3.5 w-3.5 shrink-0 animate-pulse" />
            <span className="font-bold tracking-wide">{title}</span>
            <span className="inline-block w-1.5 h-3.5 bg-primary animate-pulse ml-0.5" />
          </div>
          <span className="text-[10px] text-primary/70 hidden sm:inline">
            BUFFER: 0x4F...
          </span>
        </div>

        {/* Staggered Command Shell Rows */}
        <ol className="divide-y divide-slate-800/50 pt-1">
          {Array.from({ length: lines }, (_, index) => (
            <li
              key={index}
              className="py-2.5 flex items-start gap-4"
              style={{
                animationDelay: `${index * 80}ms`,
              }}
            >
              <span className="text-slate-600 text-right w-6 shrink-0 font-mono">
                ${index + 1}
              </span>
              <div className="flex-1 space-y-1.5">
                <div
                  className="ui-skeleton h-4 rounded"
                  style={{
                    width: index === 0 ? "70%" : index === 1 ? "45%" : index === 2 ? "85%" : "60%",
                    backgroundColor: "rgba(30, 41, 59, 0.7)",
                  }}
                />
                <div className="flex items-center gap-2 pt-1">
                  <div className="ui-skeleton h-3.5 w-20 rounded bg-orange-950/40 border border-orange-500/20" />
                  <div className="ui-skeleton h-3 w-14 rounded bg-slate-800/40" />
                </div>
              </div>
              <div className="ui-skeleton h-3 w-16 rounded bg-slate-800/60 hidden sm:block" />
            </li>
          ))}
        </ol>

        {subtitle && (
          <p className="text-[10px] text-slate-500 italic pt-1 border-t border-slate-800/40">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
