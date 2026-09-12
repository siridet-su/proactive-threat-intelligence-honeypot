"use client";

import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  CornerDownRight,
  FastForward,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatFromPath, formatTimestamp, isInitialSshEntry, statusLabel } from "./filesystemUtils";

interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  historyStatus: RegionStatus;
  historyCursor: string | null;
  selectedHistoryEventId: string | null;
  layout?: "card" | "sidebar";
  onSelectHistoryEventId: (eventId: string | null) => void;
  onLoadEarlier: () => void;
  isPlaying?: boolean;
  onTogglePlay?: () => void;
  onPause?: () => void;
  playbackSpeed?: number;
  onToggleSpeed?: () => void;
  showFailedAttempts?: boolean;
  onToggleShowFailedAttempts?: (show: boolean) => void;
}

export function CwdRouteHistory({
  selectedSession,
  history,
  historyStatus,
  historyCursor,
  selectedHistoryEventId,
  layout = "card",
  onSelectHistoryEventId,
  onLoadEarlier,
  isPlaying: controlledIsPlaying,
  onTogglePlay,
  onPause,
  playbackSpeed: controlledPlaybackSpeed,
  onToggleSpeed,
  showFailedAttempts: controlledShowFailedAttempts,
  onToggleShowFailedAttempts,
}: CwdRouteHistoryProps) {
  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);
  const [internalIsPlaying, setInternalIsPlaying] = useState(false);
  const [internalPlaybackSpeed, setInternalPlaybackSpeed] = useState<number>(1400);
  const [internalShowFailedAttempts, setInternalShowFailedAttempts] = useState(true);

  const isPlaying = controlledIsPlaying !== undefined ? controlledIsPlaying : internalIsPlaying;
  const playbackSpeed = controlledPlaybackSpeed !== undefined ? controlledPlaybackSpeed : internalPlaybackSpeed;
  const showFailedAttempts = controlledShowFailedAttempts !== undefined ? controlledShowFailedAttempts : internalShowFailedAttempts;

  const failedCount = useMemo(
    () => chronologicalHistory.filter((e) => e.action === "failed_change").length,
    [chronologicalHistory],
  );

  const displayedHistory = useMemo(() => {
    if (showFailedAttempts) return chronologicalHistory;
    return chronologicalHistory.filter((e) => e.action !== "failed_change");
  }, [chronologicalHistory, showFailedAttempts]);

  const selectedHistoryIndex = useMemo(() => {
    if (!displayedHistory.length) return -1;
    const index = displayedHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : displayedHistory.length - 1;
  }, [displayedHistory, selectedHistoryEventId]);

  const selectedHistoryEvent = selectedHistoryIndex >= 0 ? displayedHistory[selectedHistoryIndex] : null;
  const activeHistoryEventId = selectedHistoryEvent?.id ?? null;
  const isFailedHop = selectedHistoryEvent?.action === "failed_change";

  const timelineContainerRef = useRef<HTMLDivElement | null>(null);
  const activeItemRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!activeHistoryEventId) return;
    const container = timelineContainerRef.current;
    const item = activeItemRef.current;
    if (container && item) {
      const containerRect = container.getBoundingClientRect();
      const itemRect = item.getBoundingClientRect();
      const relativeItemTop = itemRect.top - containerRect.top + container.scrollTop;
      const targetScrollTop = relativeItemTop - (container.clientHeight / 2) + (itemRect.height / 2);

      container.scrollTo({
        top: Math.max(0, targetScrollTop),
        behavior: "smooth",
      });
    }
  }, [activeHistoryEventId]);

  const handlePause = useCallback(() => {
    if (onPause) {
      onPause();
    } else if (onTogglePlay) {
      if (isPlaying) onTogglePlay();
    } else {
      setInternalIsPlaying(false);
    }
  }, [isPlaying, onPause, onTogglePlay]);

  const handleTogglePlay = useCallback(() => {
    if (onTogglePlay) {
      onTogglePlay();
    } else {
      if (selectedHistoryIndex >= displayedHistory.length - 1) {
        onSelectHistoryEventId(displayedHistory[0]?.id ?? null);
      }
      setInternalIsPlaying((prev) => !prev);
    }
  }, [displayedHistory, onSelectHistoryEventId, onTogglePlay, selectedHistoryIndex]);

  // Auto-play timer (only active if not controlled externally by parent)
  useEffect(() => {
    if (controlledIsPlaying !== undefined) return;
    if (!isPlaying) return;

    const timer = setTimeout(() => {
      if (selectedHistoryIndex >= displayedHistory.length - 1) {
        setInternalIsPlaying(false);
        return;
      }

      const nextIndex = selectedHistoryIndex + 1;
      const nextEvent = displayedHistory[nextIndex];
      if (nextEvent) {
        onSelectHistoryEventId(nextEvent.id);
      } else {
        setInternalIsPlaying(false);
      }
    }, playbackSpeed);

    return () => clearTimeout(timer);
  }, [controlledIsPlaying, isPlaying, selectedHistoryIndex, displayedHistory, playbackSpeed, onSelectHistoryEventId]);

  const isSidebar = layout === "sidebar";

  return (
    <div className={`ui-panel overflow-hidden ${isSidebar ? "flex flex-col h-full min-h-0" : ""}`}>
      {/* Panel Header */}
      <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
            <h2 className="text-sm font-semibold sm:text-base truncate">
              {isSidebar ? "Session Route & Replay" : "Verified CWD route"}
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-text-subtle">
            {isSidebar
              ? "Synchronized playback: step through confirmed directory transitions."
              : "Step through Cowrie-confirmed directory transitions. Command text never creates a guessed path."}
          </p>
        </div>
        {selectedSession && (
          <span className="ui-badge shrink-0 font-mono text-xs whitespace-nowrap">
            {selectedSession.sessionId.slice(0, 12)}
          </span>
        )}
      </div>

      <div className={`p-4 ${isSidebar ? "flex flex-1 flex-col min-h-0 overflow-hidden" : ""}`}>
        {!selectedSession ? (
          <RegionState
            kind="empty"
            title="Select a session to inspect its path history"
            description="Choose a session from the topology or inspector."
          />
        ) : historyStatus === "error" && !history.length ? (
          <RegionState
            kind="error"
            title="Session history unavailable"
            description="The selected CWD history could not be loaded."
          />
        ) : historyStatus === "loading" && !history.length ? (
          <RegionState kind="loading" title="Loading session history" />
        ) : !history.length ? (
          <RegionState
            kind="empty"
            title="No verified directory transitions"
            description="This session has a known observed path, but Cowrie has not recorded a directory move. It may have ended after a non-interactive probe."
          />
        ) : (
          <>
            {/* Hop Player Deck */}
            <div className="rounded-xl border border-border bg-surface-subtle p-3" aria-live="polite">
              <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-stretch gap-2">
                <button
                  type="button"
                  className="ui-button h-auto min-h-0 shrink-0 px-2 sm:px-2.5 flex items-center justify-center gap-1 text-xs"
                  aria-label="Show previous directory move"
                  disabled={selectedHistoryIndex <= 0}
                  onClick={() => {
                    handlePause();
                    onSelectHistoryEventId(displayedHistory[selectedHistoryIndex - 1]?.id ?? null);
                  }}
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span className="hidden sm:inline">Prev</span>
                </button>

                <div
                  className={`min-w-0 rounded-lg border px-3 py-2 text-left transition-colors ${
                    isFailedHop
                      ? "border-warning-border bg-warning-subtle text-text"
                      : "border-primary-border bg-primary-subtle text-text"
                  }`}
                  title={selectedHistoryEvent?.sequence !== null ? `Event Sequence: ${selectedHistoryEvent?.sequence}` : undefined}
                >
                  <div className="flex items-center justify-between gap-2 text-xs min-w-0">
                    <div className="flex items-center gap-1.5 font-semibold uppercase tracking-[0.1em] shrink-0 whitespace-nowrap">
                      {isFailedHop && <AlertTriangle className="h-3.5 w-3.5 text-warning shrink-0" aria-hidden="true" />}
                      <span className={isFailedHop ? "text-warning" : "text-primary"}>
                        Hop {selectedHistoryIndex + 1} of {displayedHistory.length}
                      </span>
                    </div>
                    {isFailedHop ? (
                      <span className="rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-[10px] font-semibold text-warning shrink-0 whitespace-nowrap">
                        Failed Attempt
                      </span>
                    ) : (
                      <span
                        className="font-sans text-[11px] font-medium text-text-subtle truncate text-right min-w-0"
                        title={selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : undefined}
                      >
                        {selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "Loading hop"}
                      </span>
                    )}
                  </div>

                  {/* Two-Line Journey Display */}
                  <div className="mt-1.5 space-y-0.5 font-mono text-xs">
                    <div className="flex items-center gap-1.5 text-text-subtle text-[11px] min-w-0">
                      <span className="shrink-0 font-sans text-[10px] uppercase tracking-wider text-text-subtle/70">
                        from
                      </span>
                      {isInitialSshEntry(selectedHistoryEvent) ? (
                        <span className="rounded border border-border bg-surface px-1.5 py-0.5 font-sans text-[10px] font-medium text-text-subtle">
                          [SSH Login]
                        </span>
                      ) : (
                        <span className="truncate text-text-muted" title={selectedHistoryEvent?.fromPath ?? undefined}>
                          {formatFromPath(selectedHistoryEvent)}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 text-xs min-w-0">
                      <CornerDownRight
                        className={`h-3.5 w-3.5 shrink-0 ${isFailedHop ? "text-warning" : "text-primary"}`}
                        aria-hidden="true"
                      />
                      <span
                        className={`truncate font-semibold ${
                          isFailedHop ? "line-through text-text-muted/70" : "text-text"
                        }`}
                        title={selectedHistoryEvent?.toPath ?? undefined}
                      >
                        {selectedHistoryEvent?.toPath ?? "Unknown"}
                      </span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  className="ui-button h-auto min-h-0 shrink-0 px-2 sm:px-2.5 flex items-center justify-center gap-1 text-xs"
                  aria-label="Show next directory move"
                  disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
                  onClick={() => {
                    handlePause();
                    onSelectHistoryEventId(displayedHistory[selectedHistoryIndex + 1]?.id ?? null);
                  }}
                >
                  <span className="hidden sm:inline">Next</span>
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>

              {/* Playback Controls & Filters */}
              <div className="mt-2.5 flex items-center justify-between gap-1.5 border-t border-border/60 pt-2 text-xs">
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={handleTogglePlay}
                    className={`ui-button h-7 min-h-7 px-2 text-xs flex items-center gap-1 shrink-0 ${
                      isPlaying ? "border-primary bg-primary text-surface" : ""
                    }`}
                    title={isPlaying ? "Pause auto-playback" : "Play route trajectory automatically"}
                  >
                    {isPlaying ? (
                      <>
                        <Pause className="h-3 w-3" /> Pause
                      </>
                    ) : (
                      <>
                        <Play className="h-3 w-3" /> Play
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      if (onToggleSpeed) {
                        onToggleSpeed();
                      } else {
                        setInternalPlaybackSpeed((current) => (current === 1400 ? 700 : 1400));
                      }
                    }}
                    className="ui-button h-7 min-h-7 px-1.5 font-mono text-[11px] shrink-0"
                    title="Toggle playback speed (1x / 2x)"
                  >
                    {playbackSpeed === 1400 ? "1x" : "2x"}
                  </button>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {failedCount > 0 && (
                    <label className="flex items-center gap-1 text-[11px] text-text-subtle cursor-pointer select-none whitespace-nowrap shrink-0">
                      <input
                        type="checkbox"
                        checked={showFailedAttempts}
                        onChange={(e) => {
                          if (onToggleShowFailedAttempts) {
                            onToggleShowFailedAttempts(e.target.checked);
                          } else {
                            setInternalShowFailedAttempts(e.target.checked);
                          }
                        }}
                        className="rounded border-border text-primary focus:ring-primary h-3 w-3"
                      />
                      <span>Failures ({failedCount})</span>
                    </label>
                  )}

                  <button
                    type="button"
                    className="ui-button h-7 min-h-7 px-2 text-[11px] shrink-0 whitespace-nowrap"
                    disabled={selectedHistoryIndex === displayedHistory.length - 1}
                    onClick={() => {
                      handlePause();
                      onSelectHistoryEventId(displayedHistory.at(-1)?.id ?? null);
                    }}
                    title="Jump to latest recorded move"
                  >
                    <FastForward className="h-3 w-3" />
                    Latest
                  </button>
                </div>
              </div>
            </div>

            {historyCursor && (
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
                Load earlier moves
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

                  return (
                    <li key={event.id} className="relative pb-4 last:pb-0">
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
                        className={`w-full rounded-lg border px-2.5 py-2 text-left transition-colors duration-150 ${
                          isCurrent
                            ? isFailed
                              ? "border-warning-border bg-warning-subtle"
                              : "border-primary-border bg-primary-subtle"
                            : "border-transparent hover:border-border hover:bg-surface-hover"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1.5 min-w-0">
                          <p className="truncate font-medium text-xs text-text min-w-0">
                            <span className="mr-1.5 font-mono text-[11px] text-text-subtle">
                              {String(index + 1).padStart(2, "0")}
                            </span>
                            {actionLabel(event)}
                          </p>
                          <time className="shrink-0 font-mono text-[11px] text-text-subtle whitespace-nowrap ml-1">
                            {formatTimestamp(event.at)}
                          </time>
                        </div>
                        <div className="mt-1.5 space-y-0.5 font-mono text-xs">
                          {/* Line 1: Origin */}
                          <div className="flex items-center gap-1.5 text-text-subtle text-[11px] min-w-0">
                            <span className="shrink-0 font-sans text-[10px] uppercase tracking-wider text-text-subtle/70">
                              from
                            </span>
                            {isInitialSshEntry(event) ? (
                              <span className="rounded border border-border bg-surface px-1.5 py-0.5 font-sans text-[10px] font-medium text-text-subtle">
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
                              <span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-[10px] font-semibold text-warning">
                                Failed
                              </span>
                            )}
                          </div>
                        </div>
                        <div
                          className="mt-1.5 flex items-center gap-1.5 text-[11px] text-text-subtle"
                          title={event.sequence !== null ? `Event Sequence: ${event.sequence}` : undefined}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
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
                          <span>{statusLabel(event.status)}</span>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ol>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
