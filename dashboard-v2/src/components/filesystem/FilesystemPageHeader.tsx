import { Radio, Route, RefreshCw } from "lucide-react";
import type { FilesystemTopologySnapshot, FilesystemTopologySession, FilesystemClosedSession } from "@/lib/dashboardTypes";
import { formatPageBadgeText, type FreshnessState } from "./filesystemUtils";

interface FilesystemPageHeaderProps {
  viewMode: "live" | "audit";
  switchViewMode: (mode: "live" | "audit") => void;
  snapshot: FilesystemTopologySnapshot | null;
  selectedSession: FilesystemTopologySession | FilesystemClosedSession | null;
  streamState: "live" | "connecting" | "stale";
  freshnessState: FreshnessState;
  handleReconnect: () => void;
  isHydrated: boolean;
  regionStatus: string;
  refresh: () => void;
}

export function FilesystemPageHeader({
  viewMode,
  switchViewMode,
  snapshot,
  selectedSession,
  streamState,
  freshnessState,
  handleReconnect,
  isHydrated,
  regionStatus,
  refresh,
}: FilesystemPageHeaderProps) {
  return (
    <section className="flex flex-col gap-3.5 border-b border-border pb-4 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-text">Filesystem activity</h1>
        <p className="mt-0.5 max-w-2xl text-xs text-text-muted">
          {viewMode === "live"
            ? "Inspect observed Cowrie working-directory topology and live threat clusters."
            : "Step-by-step forensic route replay and directory timeline for audited attacker session."}
        </p>
      </div>

      {/* Global view controls: View switcher & real-time telemetry status */}
      <div
        className="flex flex-wrap items-center gap-2.5 sm:gap-3 shrink-0"
        role="toolbar"
        aria-label="Global filesystem controls"
      >
        {/* Mode Switcher Tabs */}
        <div
          className="flex items-center rounded-lg border border-border bg-surface-subtle p-0.5 shadow-2xs shrink-0 flex-nowrap"
          role="tablist"
          aria-label="Filesystem view modes"
        >
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "live"}
            onClick={() => switchViewMode("live")}
            className={`flex min-h-9 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
              viewMode === "live"
                ? "bg-surface text-primary shadow-xs border border-border"
                : "text-text-muted hover:text-text border border-transparent"
            }`}
          >
            <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Live Topology</span>
            {snapshot?.sessions.length ? (
              <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-xs font-mono text-text-subtle border border-border">
                {snapshot.sessions.length}
              </span>
            ) : null}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "audit"}
            onClick={() => switchViewMode("audit")}
            className={`flex min-h-9 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
              viewMode === "audit"
                ? "bg-surface text-primary shadow-xs border border-border"
                : "text-text-muted hover:text-text border border-transparent"
            }`}
          >
            <Route className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Session Audit & Replay</span>
            {selectedSession && (
              <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-xs font-mono text-text-subtle border border-border">
                .{selectedSession.sourceIp.split(".").pop()}
              </span>
            )}
          </button>
        </div>

        {/* Telemetry Status Bar & Actions */}
        <div
          className="flex items-center gap-2 shrink-0 flex-wrap sm:flex-nowrap rounded-lg border border-border/70 bg-surface-subtle/50 p-1"
          role="region"
          aria-label="Stream telemetry status"
        >
          <span
            className={`ui-badge ${
              streamState === "live"
                ? "border-success-border bg-success-subtle text-success"
                : streamState === "connecting"
                ? "border-border bg-surface-subtle text-text-subtle"
                : "border-warning-border bg-warning-subtle text-warning"
            }`}
            title={
              streamState === "live"
                ? "Real-time SSE event stream connected"
                : streamState === "connecting"
                ? "Connecting to real-time event stream"
                : "SSE event stream disconnected, reconnecting..."
            }
          >
            <Radio className={`h-3.5 w-3.5 ${streamState === "live" ? "" : "animate-pulse"}`} aria-hidden="true" />
            {streamState === "live" ? "Live stream" : streamState === "connecting" ? "Connecting" : "Reconnecting"}
          </span>

          {snapshot && (
            <span
              className={`ui-badge ${freshnessState.badgeClass}`}
              title={freshnessState.detail}
            >
              <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${freshnessState.dotClass}`} aria-hidden="true" />
              <span>{formatPageBadgeText(freshnessState)}</span>
            </span>
          )}

          {(freshnessState.isDegraded || streamState === "stale") && (
            <button
              type="button"
              className="ui-button border-warning-border bg-warning-subtle text-warning hover:bg-warning/20 font-semibold"
              onClick={handleReconnect}
              title="Force reconnect SSE stream and refresh snapshot"
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              Reconnect
            </button>
          )}

          <button
            type="button"
            className="ui-button"
            disabled={!isHydrated || regionStatus === "loading" || regionStatus === "refreshing"}
            onClick={() => {
              if (!isHydrated || regionStatus === "loading" || regionStatus === "refreshing") return;
              void refresh();
            }}
            title="Fetch fresh snapshot via HTTP"
          >
            <RefreshCw
              className={`h-4 w-4 ${regionStatus === "refreshing" || regionStatus === "loading" ? "animate-spin text-primary" : ""}`}
              aria-hidden="true"
            />
            Refresh
          </button>
        </div>
      </div>
    </section>
  );
}
