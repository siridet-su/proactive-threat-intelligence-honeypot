"use client";

import { Network, FolderTree } from "lucide-react";
import { cn } from "@/lib/utils";

interface TopologyCanvasLoaderProps {
  title?: string;
  subtitle?: string;
  className?: string;
}

export function TopologyCanvasLoader({
  title = "Mapping Decoy Filesystem Topology...",
  subtitle = "Tracing attacker working directories, file hops, and touch events",
  className,
}: TopologyCanvasLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "relative flex min-h-[360px] w-full flex-col items-center justify-center overflow-hidden rounded-xl border border-border/80 bg-surface-subtle/50 p-6 select-none",
        className
      )}
    >
      {/* Subtle Dot Grid Background */}
      <div
        className="absolute inset-0 opacity-20 pointer-events-none"
        style={{
          backgroundImage: "radial-gradient(currentColor 1px, transparent 1px)",
          backgroundSize: "20px 20px",
        }}
      />

      {/* Interactive Node Constellation */}
      <div className="relative flex items-center justify-center w-64 h-48 sm:w-80 sm:h-56">
        {/* SVG Connecting Tracers */}
        <svg
          className="absolute inset-0 h-full w-full pointer-events-none"
          viewBox="0 0 320 220"
          fill="none"
          aria-hidden="true"
        >
          {/* Connector Edges */}
          <line
            x1="160"
            y1="110"
            x2="80"
            y2="50"
            stroke="var(--primary)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="opacity-40 animate-[pti-telemetry-dash_4s_linear_infinite]"
          />
          <line
            x1="160"
            y1="110"
            x2="240"
            y2="60"
            stroke="var(--info)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="opacity-40 animate-[pti-telemetry-dash_4s_linear_infinite]"
          />
          <line
            x1="160"
            y1="110"
            x2="90"
            y2="170"
            stroke="var(--chart-4)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="opacity-30"
          />
          <line
            x1="160"
            y1="110"
            x2="230"
            y2="165"
            stroke="var(--danger)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="opacity-30"
          />
        </svg>

        {/* Center Root Node (/root or honeypot core) */}
        <div className="relative z-10 flex flex-col items-center gap-1">
          <div className="relative flex h-12 w-12 items-center justify-center rounded-xl border-2 border-primary bg-surface shadow-[0_0_16px_var(--primary)]">
            <FolderTree className="h-5 w-5 text-primary animate-pulse" />
            <span className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-primary animate-ping" />
          </div>
          <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-[10px] font-bold text-text border border-border">
            /
          </span>
        </div>

        {/* Orbit Node 1: /bin or /tmp */}
        <div className="absolute top-4 left-12 flex flex-col items-center gap-1">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/50 bg-surface shadow-xs">
            <span className="h-2 w-2 rounded-full bg-primary" />
          </div>
          <span className="font-mono text-[9px] text-text-subtle">/tmp</span>
        </div>

        {/* Orbit Node 2: /etc */}
        <div className="absolute top-6 right-14 flex flex-col items-center gap-1">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-info/50 bg-surface shadow-xs">
            <span className="h-2 w-2 rounded-full bg-info" />
          </div>
          <span className="font-mono text-[9px] text-text-subtle">/etc</span>
        </div>

        {/* Orbit Node 3: /var/log */}
        <div className="absolute bottom-6 left-16 flex flex-col items-center gap-1">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface">
            <span className="h-1.5 w-1.5 rounded-full bg-text-subtle" />
          </div>
          <span className="font-mono text-[9px] text-text-subtle">/var</span>
        </div>

        {/* Orbit Node 4: Dropped payload */}
        <div className="absolute bottom-5 right-16 flex flex-col items-center gap-1">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-danger/50 bg-surface">
            <span className="h-1.5 w-1.5 rounded-full bg-danger animate-pulse" />
          </div>
          <span className="font-mono text-[9px] text-danger font-semibold">/malware</span>
        </div>
      </div>

      {/* Status Readout */}
      <div className="mt-3 flex flex-col items-center gap-1">
        <div className="inline-flex items-center gap-2 rounded-full border border-primary-border bg-primary-subtle px-3 py-1 font-mono text-xs font-semibold text-primary">
          <Network className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
          <span>{title}</span>
        </div>
        <p className="max-w-md text-xs text-text-muted text-center font-sans">
          {subtitle}
        </p>
      </div>
    </div>
  );
}
