"use client";

import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface ChartLaserLoaderProps {
  title?: string;
  className?: string;
  height?: string | number;
}

export function ChartLaserLoader({
  title = "Analyzing Telemetry Waveform...",
  className,
}: ChartLaserLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "relative flex h-full w-full flex-col justify-between overflow-hidden rounded-lg border border-border/60 bg-surface-subtle/40 p-4 select-none",
        className
      )}
    >
      {/* Top Meta Line */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-primary animate-pulse" aria-hidden="true" />
          <span className="font-mono text-[11px] font-semibold tracking-wider uppercase text-primary">
            {title}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="ui-skeleton h-2.5 w-12 rounded-sm" />
          <div className="ui-skeleton h-2.5 w-16 rounded-sm" />
        </div>
      </div>

      {/* Grid Canvas & Simulated Laser Waveform */}
      <div className="relative my-2 flex-1 min-h-[120px] w-full overflow-hidden">
        {/* Horizontal & Vertical Grid Lines */}
        <div className="absolute inset-0 grid grid-rows-4 divide-y divide-border/30">
          <div />
          <div />
          <div />
          <div />
        </div>
        <div className="absolute inset-0 grid grid-cols-6 divide-x divide-border/20">
          <div />
          <div />
          <div />
          <div />
          <div />
          <div />
        </div>

        {/* Laser Scanning Beam */}
        <div
          className="absolute inset-y-0 w-24 pointer-events-none"
          style={{
            background:
              "linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--primary) 28%, transparent) 50%, color-mix(in srgb, var(--primary) 65%, transparent) 95%, #ffffff 100%)",
            animation: "pti-laser-scan 2.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
          }}
        />

        {/* Simulated Waveform Path */}
        <svg
          className="absolute inset-0 h-full w-full"
          preserveAspectRatio="none"
          viewBox="0 0 400 100"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="chartWaveFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--chart-1)" stopOpacity="0.25" />
              <stop offset="100%" stopColor="var(--chart-1)" stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {/* Shaded Area */}
          <path
            d="M 0 80 Q 50 20, 100 65 T 200 40 T 300 70 T 400 35 L 400 100 L 0 100 Z"
            fill="url(#chartWaveFill)"
          />
          {/* Wave Line */}
          <path
            d="M 0 80 Q 50 20, 100 65 T 200 40 T 300 70 T 400 35"
            fill="none"
            stroke="var(--chart-1)"
            strokeWidth="2"
            strokeDasharray="4 4"
            className="opacity-70"
          />
        </svg>
      </div>

      {/* Time Axis Pill Skeletons */}
      <div className="flex items-center justify-between border-t border-border/40 pt-2 font-mono text-[10px] text-text-subtle">
        <div className="ui-skeleton h-2 w-10" />
        <div className="ui-skeleton h-2 w-10 hidden sm:block" />
        <div className="ui-skeleton h-2 w-10 hidden sm:block" />
        <div className="ui-skeleton h-2 w-10" />
        <div className="ui-skeleton h-2 w-10" />
      </div>
    </div>
  );
}
