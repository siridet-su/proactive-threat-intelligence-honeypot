"use client";

import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface ChartLaserLoaderProps {
  title?: string;
  className?: string;
  height?: string | number;
}

export function ChartLaserLoader({
  title = "Analyzing telemetry waveform…",
  className,
}: ChartLaserLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border border-border bg-surface-subtle p-3.5 select-none",
        className
      )}
    >
      {/* Top Meta Line matching SOC Chart headers */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-primary animate-pulse" aria-hidden="true" />
          <span className="text-xs font-semibold text-text tracking-normal">
            {title}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-text-subtle">
            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-ping" />
            LIVE TELEMETRY
          </span>
        </div>
      </div>

      {/* Grid Canvas & Simulated Laser Telemetry Baseline */}
      <div className="relative my-2 flex-1 min-h-[120px] w-full flex">
        {/* Y-Axis Ticks */}
        <div className="w-[30px] shrink-0 flex flex-col justify-between py-1 text-right pr-2 font-mono text-[9px] text-text-subtle/70 tabular-nums">
          <span>100</span>
          <span>75</span>
          <span>50</span>
          <span>25</span>
          <span>0</span>
        </div>

        {/* Canvas Area */}
        <div className="relative flex-1 h-full min-h-0 overflow-hidden border-b border-border/40">
          {/* Horizontal Dashed Grid Lines */}
          <div className="absolute inset-0 flex flex-col justify-between pointer-events-none py-1">
            <div className="w-full border-b border-dashed border-border/40" />
            <div className="w-full border-b border-dashed border-border/40" />
            <div className="w-full border-b border-dashed border-border/40" />
            <div className="w-full border-b border-dashed border-border/40" />
            <div className="w-full border-b border-dashed border-border/40" />
          </div>

          {/* Laser Scanning Beam */}
          <div
            className="absolute inset-y-0 w-28 pointer-events-none z-10"
            style={{
              background:
                "linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--primary) 12%, transparent) 50%, color-mix(in srgb, var(--primary) 28%, transparent) 95%, transparent 100%)",
              animation: "pti-laser-scan 2.4s cubic-bezier(0.4, 0, 0.2, 1) infinite",
            }}
          />

          {/* Realistic Telemetry Baseline Guide */}
          <svg
            className="absolute inset-0 h-full w-full"
            preserveAspectRatio="none"
            viewBox="0 0 400 100"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="chartLaserFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--chart-1)" stopOpacity="0.16" />
                <stop offset="100%" stopColor="var(--chart-1)" stopOpacity="0.01" />
              </linearGradient>
            </defs>
            {/* Shaded Area */}
            <path
              d="M 0 88 Q 100 85, 200 89 T 300 86 T 400 88 L 400 100 L 0 100 Z"
              fill="url(#chartLaserFill)"
            />
            {/* Baseline Trace */}
            <path
              d="M 0 88 Q 100 85, 200 89 T 300 86 T 400 88"
              fill="none"
              stroke="var(--chart-1)"
              strokeWidth="1.75"
              strokeDasharray="4 2"
              className="opacity-75"
            />
          </svg>
        </div>
      </div>

      {/* Time Axis */}
      <div className="flex items-center justify-between pl-[30px] font-mono text-[9px] text-text-subtle/60 tabular-nums">
        <span>-30s</span>
        <span className="hidden sm:inline">-20s</span>
        <span className="hidden sm:inline">-10s</span>
        <span>live</span>
      </div>
    </div>
  );
}
