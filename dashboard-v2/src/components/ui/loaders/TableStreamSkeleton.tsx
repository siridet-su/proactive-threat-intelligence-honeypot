"use client";

import { cn } from "@/lib/utils";

interface TableStreamSkeletonProps {
  rows?: number;
  variant?: "threat-intel" | "malware" | "compact";
  className?: string;
}

export function TableStreamSkeleton({
  rows = 5,
  variant = "threat-intel",
  className,
}: TableStreamSkeletonProps) {
  return (
    <div
      role="status"
      aria-label="Loading table records"
      className={cn("divide-y divide-border/60 overflow-hidden", className)}
    >
      {Array.from({ length: rows }, (_, row) => (
        <div
          key={row}
          className="flex items-center justify-between gap-4 px-5 py-3 transition-colors hover:bg-surface-hover/30"
          style={{ animationDelay: `${row * 60}ms` }}
        >
          {variant === "threat-intel" && (
            <>
              {/* Session ID + Severity Dot */}
              <div className="flex items-center gap-2.5 w-[200px] shrink-0">
                <span className="h-2 w-2 rounded-full bg-border-strong/60 animate-pulse shrink-0" />
                <div className="ui-skeleton h-4 w-28" />
              </div>

              {/* Origin IP Monospace */}
              <div className="hidden sm:flex items-center gap-1.5 w-[140px] shrink-0">
                <div className="ui-skeleton h-4 w-24" />
              </div>

              {/* Timestamp */}
              <div className="hidden md:flex items-center gap-1.5 w-[160px] shrink-0">
                <div className="ui-skeleton h-3.5 w-28" />
              </div>

              {/* Attacker Type Badge */}
              <div className="flex-1 min-w-0">
                <div className="ui-skeleton h-5 w-20 rounded-full" />
              </div>

              {/* Action / Status Pill */}
              <div className="w-[80px] shrink-0 flex justify-end">
                <div className="ui-skeleton h-4 w-12 rounded" />
              </div>
            </>
          )}

          {variant === "malware" && (
            <>
              {/* IP / Timestamp */}
              <div className="space-y-1.5 w-[180px] shrink-0">
                <div className="ui-skeleton h-4 w-28" />
                <div className="ui-skeleton h-3 w-32" />
              </div>

              {/* Malware Type Badge */}
              <div className="w-[120px] shrink-0">
                <div className="ui-skeleton h-6 w-24 rounded-full" />
              </div>

              {/* File details / URL */}
              <div className="flex-1 min-w-0 space-y-1">
                <div className="ui-skeleton h-4 w-36" />
                <div className="ui-skeleton h-3 w-16" />
              </div>

              {/* SHA-256 Hash box */}
              <div className="hidden lg:block w-[180px] shrink-0">
                <div className="ui-skeleton h-5 w-40 font-mono" />
              </div>

              {/* Action Button */}
              <div className="w-[50px] shrink-0 flex justify-end">
                <div className="ui-skeleton h-8 w-8 rounded-lg" />
              </div>
            </>
          )}

          {variant === "compact" && (
            <>
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <span className="h-1.5 w-1.5 rounded-full bg-border-strong animate-pulse" />
                <div className="ui-skeleton h-3.5 w-32" />
              </div>
              <div className="ui-skeleton h-3.5 w-16 shrink-0" />
            </>
          )}
        </div>
      ))}
    </div>
  );
}
