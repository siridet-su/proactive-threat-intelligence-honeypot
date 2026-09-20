import { Radio } from "lucide-react";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";

export function LiveScopeBar({ snapshot }: { snapshot: FilesystemTopologySnapshot | null }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-border bg-surface px-3 py-2 shadow-xs">
      <div className="flex items-center gap-2">
        <Radio className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold text-text">Live Topology</span>
        {snapshot?.sessions.length ? (
          <span className="rounded-full bg-surface-subtle px-2 py-0.5 text-xs font-mono text-text-subtle border border-border">
            {snapshot.sessions.length} Active Sessions
          </span>
        ) : null}
      </div>
    </div>
  );
}
