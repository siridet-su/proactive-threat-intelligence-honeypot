"use client";

import { useId } from "react";
import { cn } from "@/lib/utils";

export interface ChartLineWireframe {
  name: string;
  color: string;
  fill?: string;
  baselineYPercent?: number; // 0 (top) to 100 (bottom)
}

export interface ChartWireframeSkeletonProps {
  title: string;
  description: string;
  lines: ChartLineWireframe[];
  yTicks?: (number | string)[];
  xTicks?: string[];
  className?: string;
  chartHeightClassName?: string;
  mode?: "area" | "line";
  scanBeam?: boolean;
}

export function ChartWireframeSkeleton({
  title,
  description,
  lines,
  yTicks = [100, 75, 50, 25, 0],
  xTicks = ["-30s", "-24s", "-18s", "-12s", "-6s", "live"],
  className,
  chartHeightClassName = "h-[180px]",
  mode = "area",
  scanBeam = true,
}: ChartWireframeSkeletonProps) {
  const gradientId = useId();

  return (
    <section
      role="status"
      aria-label={`Loading ${title}`}
      className={cn(
        "relative flex flex-col rounded-xl border border-border bg-surface-subtle p-3.5 select-none overflow-hidden",
        className
      )}
    >
      {/* Chart Header matching LiveChart */}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="text-xs font-semibold text-text">{title}</h3>
          <p className="mt-0.5 text-[11px] text-text-subtle">{description}</p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-x-2.5 gap-y-1 text-[10px] text-text-subtle">
          {lines.map((line) => (
            <span key={line.name} className="inline-flex items-center gap-1">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: line.color }}
              />
              {line.name}
            </span>
          ))}
        </div>
      </div>

      {/* Chart Body with Recharts-identical Layout */}
      <div className={cn("mt-2 min-h-0 flex-1 flex flex-col", chartHeightClassName)}>
        <div className="relative flex-1 flex min-h-0">
          {/* Y-Axis: exact 34px width matching <YAxis width={34} /> */}
          <div className="w-[34px] shrink-0 flex flex-col justify-between py-0.5 text-right pr-2 font-mono text-[10px] text-text-subtle/70 tabular-nums">
            {yTicks.map((tick, i) => (
              <span key={i} className="leading-none">{tick}</span>
            ))}
          </div>

          {/* Canvas Area with CartesianGrid & Baseline Guides */}
          <div className="relative flex-1 h-full min-h-0 overflow-hidden border-b border-border/40">
            {/* Horizontal Dashed Grid Lines */}
            <div className="absolute inset-0 flex flex-col justify-between pointer-events-none py-0.5">
              {yTicks.map((_, i) => (
                <div
                  key={i}
                  className="w-full border-b border-dashed border-border/40"
                />
              ))}
            </div>

            {/* Subtle Laser Scan Beam */}
            {scanBeam && (
              <div
                className="pointer-events-none absolute inset-y-0 w-32 z-10"
                style={{
                  background:
                    "linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--primary) 12%, transparent) 50%, color-mix(in srgb, var(--primary) 28%, transparent) 95%, transparent 100%)",
                  animation: "pti-laser-scan 2.2s cubic-bezier(0.4, 0, 0.2, 1) infinite",
                }}
              />
            )}

            {/* Simulated Telemetry Baseline SVG */}
            <svg
              className="absolute inset-0 h-full w-full"
              preserveAspectRatio="none"
              viewBox="0 0 500 150"
              aria-hidden="true"
            >
              <defs>
                {lines.map((line, idx) => (
                  <linearGradient
                    key={line.name}
                    id={`${gradientId}-fill-${idx}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="0%" stopColor={line.fill || line.color} stopOpacity="0.16" />
                    <stop offset="100%" stopColor={line.fill || line.color} stopOpacity="0.01" />
                  </linearGradient>
                ))}
              </defs>

              {lines.map((line, idx) => {
                // Baseline percentage: 0 is top, 100 is bottom
                const targetPercent = line.baselineYPercent ?? (idx === 0 ? 92 : idx === 1 ? 68 : 48);
                const y = (targetPercent / 100) * 150;
                const pathD = `M 0 ${y} Q 125 ${y - 3}, 250 ${y + 2} T 375 ${y - 2} T 500 ${y}`;
                const areaD = `${pathD} L 500 150 L 0 150 Z`;

                return (
                  <g key={line.name} className="opacity-80">
                    {mode === "area" && line.fill && (
                      <path d={areaD} fill={`url(#${gradientId}-fill-${idx})`} />
                    )}
                    <path
                      d={pathD}
                      fill="none"
                      stroke={line.color}
                      strokeWidth="1.75"
                      strokeDasharray="4 2"
                      className="opacity-75"
                    />
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* X-Axis: Timestamps matching Recharts bottom axis */}
        <div className="flex justify-between pl-[34px] pt-1.5 font-mono text-[9px] text-text-subtle/60 tabular-nums">
          {xTicks.map((tick, i) => (
            <span key={i}>{tick}</span>
          ))}
        </div>
      </div>
    </section>
  );
}
