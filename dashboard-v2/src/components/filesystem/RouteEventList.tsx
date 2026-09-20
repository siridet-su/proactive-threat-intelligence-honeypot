import { AlertCircle, Clock, CornerDownRight, Plus, RefreshCw } from "lucide-react";
import type { RegionStatus } from "@/components/ui/RegionState";
import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatFromPath, formatTimestamp, isInitialSshEntry, statusLabel } from "./filesystemUtils";

export interface RouteEventListProps {
  historyComplete: boolean;
  historyCursor: string | null;
  historyStatus: RegionStatus;
  historyLength: number;
  historyTotalItems: number;
  replayTimeline: import("./filesystemUtils").ReplayTimeline;
  onLoadEarlier: () => void;
  timelineContainerRef: React.RefObject<HTMLDivElement | null>;
  isSidebar: boolean;
  displayedHistory: SessionCwdHistoryEvent[];
  activeHistoryEventId: string | null;
  timeMetrics: {
    hopMetrics: Array<{
      deltaMs: number;
      formattedDelta: string;
      formattedElapsed: string;
    }>;
  };
  activeItemRef: React.RefObject<HTMLButtonElement | null>;
  handlePause: () => void;
  onSelectHistoryEventId: (eventId: string | null) => void;
  displayedHistoryMetrics: {
    indexOffset: number;
  };
  anchoredHop: SessionCwdHistoryEvent | null;
  isAnchoredSelected: boolean;
  showFailedAttempts: boolean;
}

export function RouteEventList({
  historyComplete,
  historyCursor,
  historyStatus,
  historyLength,
  historyTotalItems,
  replayTimeline,
  onLoadEarlier,
  timelineContainerRef,
  isSidebar,
  displayedHistory,
  activeHistoryEventId,
  timeMetrics,
  activeItemRef,
  handlePause,
  onSelectHistoryEventId,
  displayedHistoryMetrics,
  anchoredHop,
  isAnchoredSelected,
  showFailedAttempts,
}: RouteEventListProps) {
  return (
    <>
      <div className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-text-subtle" aria-live="polite">
        <span>{historyComplete
          ? replayTimeline.durationScope === "retained" ? "Complete retained history loaded" : "Complete displayed history loaded"
          : `${replayTimeline.durationLabel} · ${historyLength} of ${historyTotalItems} retained events loaded`}</span>
        <span className="shrink-0 font-mono">{historyTotalItems} total</span>
      </div>

      {!historyComplete && historyCursor && (
        <button
          type="button"
          className="ui-button mt-3"
          onClick={onLoadEarlier}
          disabled={historyStatus === "refreshing"}
        >
          {historyStatus === "refreshing" ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Plus className="h-4 w-4" />
          )}
          Load earlier moves ({Math.max(0, historyTotalItems - historyLength)} remaining)
        </button>
      )}

      {/* Scrollable Timeline List */}
      <div
        ref={timelineContainerRef}
        className={`mt-4 ${isSidebar ? "flex-1 min-h-0 overflow-y-auto overscroll-contain pr-1 pb-4" : ""}`}
      >
        <ol className="relative space-y-0 border-l border-border pl-5" aria-label="Verified directory route">
          {displayedHistory.map((event, index) => {
            const isCurrent = event.id === activeHistoryEventId;
            const isFailed = event.action === "failed_change";
            const hopMetric = timeMetrics.hopMetrics[index];
            const isPauseDetected = (hopMetric?.deltaMs ?? 0) >= 60_000;

            return (
              <li key={event.id} className="relative pb-2.5 last:pb-0">
                {index > 0 && isPauseDetected && (
                  <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-mono text-warning select-none">
                    <div className="h-px w-3 bg-warning/40" aria-hidden="true" />
                    <span className="inline-flex items-center gap-1 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 text-[10px] font-medium">
                      <Clock className="h-2.5 w-2.5" aria-hidden="true" />
                      Attacker pause: +{hopMetric?.formattedDelta}
                    </span>
                  </div>
                )}
                <span
                  className={`absolute -left-[27px] top-2.5 flex h-2.5 w-2.5 rounded-full border-2 border-surface ${
                    isFailed
                      ? "bg-warning ring-2 ring-warning/30"
                      : isCurrent
                        ? "bg-primary ring-2 ring-primary/40"
                        : "bg-border-strong"
                  }`}
                  aria-hidden="true"
                />
                <button
                  type="button"
                  ref={isCurrent ? activeItemRef : undefined}
                  aria-current={isCurrent ? "step" : undefined}
                  onClick={() => {
                    handlePause();
                    onSelectHistoryEventId(event.id);
                  }}
                  className={`w-full rounded-lg border px-2.5 py-1.5 text-left transition-colors duration-150 ${
                    isCurrent
                      ? isFailed
                        ? "border-warning-border bg-warning-subtle"
                        : "border-primary-border bg-primary-subtle"
                      : "border-transparent hover:border-border hover:bg-surface-hover"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5 min-w-0">
                    <p className="truncate font-medium text-xs text-text min-w-0">
                      <span className="mr-1.5 font-mono text-xs text-text-subtle">
                        {String(displayedHistoryMetrics.indexOffset + index + 1).padStart(2, "0")}
                      </span>
                      {actionLabel(event)}
                    </p>
                    <time className="shrink-0 font-mono text-xs text-text-subtle whitespace-nowrap ml-1 flex items-center gap-1.5">
                      <span>{formatTimestamp(event.at)}</span>
                      <span className="rounded bg-surface px-1 py-0.2 border border-border/60 text-[10px] text-text-muted">
                        {hopMetric?.formattedElapsed ?? "+00:00"}
                      </span>
                    </time>
                  </div>
                  <div className="mt-1.5 space-y-0.5 font-mono text-xs">
                    {/* Line 1: Origin */}
                    <div className="flex items-center gap-1.5 text-text-subtle text-xs min-w-0">
                      <span className="shrink-0 font-sans text-xs uppercase tracking-wider text-text-subtle/70">
                        from
                      </span>
                      {isInitialSshEntry(event) ? (
                        <span className="rounded border border-border bg-surface px-1.5 py-0.5 font-sans text-xs font-medium text-text-subtle">
                          [SSH Login]
                        </span>
                      ) : (
                        <span className="truncate text-text-muted" title={event.fromPath ?? undefined}>
                          {formatFromPath(event)}
                        </span>
                      )}
                    </div>

                    {/* Line 2: Destination */}
                    <div className="flex items-center gap-1.5 text-xs min-w-0">
                      <CornerDownRight
                        className={`h-3.5 w-3.5 shrink-0 ${isFailed ? "text-warning" : "text-primary"}`}
                        aria-hidden="true"
                      />
                      <span
                        className={`truncate font-semibold ${
                          isFailed ? "line-through text-text-muted/60" : "text-text"
                        }`}
                        title={event.toPath ?? undefined}
                      >
                        {event.toPath ?? "Unknown"}
                      </span>
                      {isFailed && (
                        <span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-xs font-semibold text-warning flex items-center gap-1">
                          <AlertCircle className="h-3 w-3" /> Failed
                        </span>
                      )}
                    </div>
                  </div>
                  <div
                    className="mt-1.5 flex items-center justify-between gap-1.5 text-xs text-text-subtle"
                    title={event.sequence !== null ? `Event Sequence: ${event.sequence}` : undefined}
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                          event.status === "confirmed"
                            ? "bg-success"
                            : event.status === "conditional_candidate"
                              ? "bg-warning"
                              : isFailed
                                ? "bg-warning"
                                : "bg-info"
                        }`}
                        aria-hidden="true"
                      />
                      <span className="truncate">{statusLabel(event.status)}</span>
                    </div>

                    <span
                      className={`inline-flex shrink-0 items-center gap-1 font-mono text-[10px] px-1.5 py-0.5 rounded ${
                        isPauseDetected
                          ? "bg-warning-subtle text-warning border border-warning-border font-medium"
                          : "text-text-subtle bg-surface border border-border/50"
                      }`}
                      title={`Dwell before this hop: ${hopMetric?.formattedDelta ?? "0s"}`}
                    >
                      <Clock className="h-2.5 w-2.5" aria-hidden="true" />
                      <span>{index === 0 ? "Entry" : `+${hopMetric?.formattedDelta ?? "0s"}`}</span>
                    </span>
                  </div>
                </button>
              </li>
            );
          })}

          {/* Explicit unloaded gap & anchored hop target */}
          {anchoredHop && !displayedHistory.some((e) => e.id === anchoredHop.id) && (
            <>
              <li className="relative my-3 pl-2" data-testid="unloaded-gap-callout">
                <div className="rounded-lg border border-dashed border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-200/90 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-mono">
                    <AlertCircle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    <span>Unloaded history gap</span>
                  </div>
                  {!historyComplete && (
                    <button
                      type="button"
                      onClick={onLoadEarlier}
                      className="rounded bg-amber-500/20 px-2 py-0.5 font-medium text-amber-100 hover:bg-amber-500/30 transition-colors text-[11px]"
                    >
                      Load earlier
                    </button>
                  )}
                </div>
              </li>

              <li key={anchoredHop.id} className="relative pb-2.5 last:pb-0" data-testid="anchored-hop-card">
                <span
                  className={`absolute -left-[27px] top-2.5 flex h-2.5 w-2.5 rounded-full border-2 border-surface ${
                    isAnchoredSelected ? "bg-primary ring-2 ring-primary/40" : "bg-border-strong"
                  }`}
                  aria-hidden="true"
                />
                <button
                  type="button"
                  aria-current={isAnchoredSelected ? "step" : undefined}
                  onClick={() => {
                    handlePause();
                    onSelectHistoryEventId(anchoredHop.id);
                  }}
                  className={`w-full rounded-lg border px-2.5 py-1.5 text-left transition-colors duration-150 ${
                    isAnchoredSelected
                      ? "border-primary-border bg-primary-subtle"
                      : "border-transparent hover:border-border hover:bg-surface-hover"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5 min-w-0">
                    <p className="truncate font-medium text-xs text-text min-w-0">
                      <span className="mr-1.5 font-mono text-xs text-text-subtle">
                        {String((showFailedAttempts ? anchoredHop.hopNumber : anchoredHop.successfulHopNumber ?? anchoredHop.hopNumber) ?? 1).padStart(2, "0")}
                      </span>
                      {actionLabel(anchoredHop)}
                      <span className="ml-1.5 rounded bg-amber-500/20 px-1 py-0.2 text-[10px] text-amber-300 font-sans">
                        Anchored
                      </span>
                    </p>
                    <time className="shrink-0 font-mono text-xs text-text-subtle whitespace-nowrap ml-1">
                      {formatTimestamp(anchoredHop.at)}
                    </time>
                  </div>
                  <div className="mt-1.5 flex items-center gap-1.5 text-xs min-w-0 font-mono text-text-subtle">
                    <span>{formatFromPath(anchoredHop)}</span>
                    <span>→</span>
                    <strong className="text-text truncate">{anchoredHop.toPath ?? "Unknown"}</strong>
                  </div>
                </button>
              </li>
            </>
          )}
        </ol>
      </div>
    </>
  );
}
