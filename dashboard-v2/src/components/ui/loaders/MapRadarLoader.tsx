"use client";

import { Radio, Crosshair } from "lucide-react";
import { cn } from "@/lib/utils";

interface MapRadarLoaderProps {
  title?: string;
  subtitle?: string;
  className?: string;
}

export function MapRadarLoader({
  title = "Scanning Global Telemetry Grid",
  subtitle = "Synchronizing live honeypot sensor feeds & geo-coordinates...",
  className,
}: MapRadarLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "absolute inset-0 z-20 flex flex-col items-center justify-center bg-surface/75 backdrop-blur-[2px] p-6 text-center select-none",
        className
      )}
    >
      {/* Central Radar Screen */}
      <div className="relative flex items-center justify-center w-48 h-48 sm:w-56 sm:h-56">
        {/* Outer Grid & Concentric Rings */}
        <div className="absolute inset-0 rounded-full border border-border/80" />
        <div className="absolute inset-4 rounded-full border border-dashed border-primary/30" />
        <div className="absolute inset-12 rounded-full border border-primary/40" />
        <div className="absolute inset-20 rounded-full border border-primary/20" />
        <div className="absolute inset-0 rounded-full border border-primary/20 animate-ping opacity-20 [animation-duration:3s]" />

        {/* Crosshair Axis Lines */}
        <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-gradient-to-r from-transparent via-primary/30 to-transparent" />
        <div className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-gradient-to-b from-transparent via-primary/30 to-transparent" />

        {/* Diagonal Corner Marks */}
        <Crosshair className="absolute h-5 w-5 text-primary/40" aria-hidden="true" />

        {/* Rotating Radar Sweep Cone */}
        <div
          className="absolute inset-0 rounded-full pointer-events-none"
          style={{
            background:
              "conic-gradient(from 0deg, transparent 0deg 270deg, color-mix(in srgb, var(--primary) 22%, transparent) 360deg)",
            animation: "pti-radar-sweep 3.2s linear infinite",
          }}
        />

        {/* Center Node / Radar Core */}
        <div className="relative z-10 flex items-center justify-center">
          <span className="absolute h-4 w-4 rounded-full bg-primary/30 animate-ping" />
          <span className="h-2.5 w-2.5 rounded-full bg-primary shadow-[0_0_8px_var(--primary)]" />
        </div>

        {/* Orbital Target Blip */}
        <span
          className="absolute top-8 right-12 h-2 w-2 rounded-full bg-danger animate-pulse shadow-[0_0_6px_var(--danger)]"
          aria-hidden="true"
        />
        <span
          className="absolute bottom-12 left-10 h-1.5 w-1.5 rounded-full bg-info animate-pulse shadow-[0_0_5px_var(--info)] [animation-delay:1s]"
          aria-hidden="true"
        />
      </div>

      {/* Cyber Status Readout */}
      <div className="mt-4 flex flex-col items-center gap-1.5">
        <div className="inline-flex items-center gap-2 rounded-full border border-primary-border bg-primary-subtle px-3 py-1 text-xs font-mono font-semibold uppercase tracking-wider text-primary">
          <Radio className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
          <span>{title}</span>
        </div>
        <p className="max-w-xs text-xs text-text-muted font-sans sm:max-w-sm">
          {subtitle}
        </p>
      </div>
    </div>
  );
}
