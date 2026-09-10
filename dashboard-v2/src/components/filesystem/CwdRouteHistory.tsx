"use client";

import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  FastForward,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatTimestamp, statusLabel } from "./filesystemUtils";

interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  historyStatus: RegionStatus;
  historyCursor: string | null;
  selectedHistoryEventId: string | null;
  layout?: "card" | "sidebar";
  onSelectHistoryEventId: (eventId: string | null) => void;
  onLoadEarlier: () => void;
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
}: CwdRouteHistoryProps) {
  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1400);
  const [showFailedAttempts, setShowFailedAttempts] = useState(true);

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

  // Auto-play timer
  useEffect(() => {
    if (!isPlaying) return;

    const timer = setTimeout(() => {
      if (selectedHistoryIndex >= displayedHistory.length - 1) {
        setIsPlaying(false);
        return;
      }

      const nextIndex = selectedHistoryIndex + 1;
      const nextEvent = displayedHistory[nextIndex];
      if (nextEvent) {
        onSelectHistoryEventId(nextEvent.id);
      } else {
        setIsPlaying(false);
      }
    }, playbackSpeed);

    return () => clearTimeout(timer);
  }, [isPlaying, selectedHistoryIndex, displayedHistory, playbackSpeed, onSelectHistoryEventId]);

  const isSidebar = layout === "sidebar";

  return (
    <div className={`ui-panel overflow-hidden ${isSidebar ? "flex flex-col h-full min-h-[500px]" : ""}`}>
      {/* Panel Header */}
      <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 className="text-sm font-semibold sm:text-base">
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
          <span className="ui-badge shrink-0 font-mono text-xs">
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
                  className="ui-button h-auto min-h-0 w-9 shrink-0 p-0 sm:w-auto sm:px-3"
                  aria-label="Show previous directory move"
                  disabled={selectedHistoryIndex <= 0}
                  onClick={() => {
                    setIsPlaying(false);
                    onSelectHistoryEventId(displayedHistory[selectedHistoryIndex - 1]?.id ?? null);
                  }}
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span className="hidden sm:inline">Prev</span>
                </button>

                <div
                  className={`min-w-0 rounded-lg border px-3 py-2 text-center transition-colors ${
                    isFailedHop
                      ? "border-warning-border bg-warning-subtle text-text"
                      : "border-primary-border bg-primary-subtle text-text"
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 text-xs font-semibold uppercase tracking-[0.12em]">
                    {isFailedHop && <AlertTriangle className="h-3.5 w-3.5 text-warning" aria-hidden="true" />}
                    <span className={isFailedHop ? "text-warning" : "text-primary"}>
                      Hop {selectedHistoryIndex + 1} of {displayedHistory.length}
                    </span>
                    {isFailedHop && <span className="text-[10px] text-warning font-normal lowercase">(failed)</span>}
                  </div>
                  <p className="mt-0.5 truncate font-medium text-xs sm:text-sm text-text">
                    {selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "Loading hop"}
                  </p>
                  <p className="mt-0.5 truncate font-mono text-xs text-text-muted">
                    <span>{selectedHistoryEvent?.fromPath ?? "Unknown"}</span>
                    <span className={`px-1.5 font-bold ${isFailedHop ? "text-warning" : "text-primary"}`}>
                      {isFailedHop ? "⇏" : "→"}
                    </span>
                    <span className={isFailedHop ? "line-through text-text-muted/70" : ""}>
                      {selectedHistoryEvent?.toPath ?? "Unknown"}
                    </span>
                  </p>
                </div>

                <button
                  type="button"
                  className="ui-button h-auto min-h-0 w-9 shrink-0 p-0 sm:w-auto sm:px-3"
                  aria-label="Show next directory move"
                  disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
                  onClick={() => {
                    setIsPlaying(false);
                    onSelectHistoryEventId(displayedHistory[selectedHistoryIndex + 1]?.id ?? null);
                  }}
                >
                  <span className="hidden sm:inline">Next</span>
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>

              {/* Playback Controls & Filters */}
              <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-border/60 pt-2 text-xs">
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedHistoryIndex >= displayedHistory.length - 1) {
                        onSelectHistoryEventId(displayedHistory[0]?.id ?? null);
                      }
                      setIsPlaying(!isPlaying);
                    }}
                    className={`ui-button h-7 min-h-7 px-2 text-xs flex items-center gap-1 ${
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
                    onClick={() => setPlaybackSpeed(playbackSpeed === 1400 ? 700 : 1400)}
                    className="ui-button h-7 min-h-7 px-1.5 font-mono text-[11px]"
                    title="Toggle playback speed (1x / 2x)"
                  >
                    {playbackSpeed === 1400 ? "1x" : "2x"}
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  {failedCount > 0 && (
                    <label className="flex items-center gap-1 text-[11px] text-text-subtle cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={showFailedAttempts}
                        onChange={(e) => setShowFailedAttempts(e.target.checked)}
                        className="rounded border-border text-primary focus:ring-primary h-3 w-3"
                      />
                      <span>Failures ({failedCount})</span>
                    </label>
                  )}

                  <button
                    type="button"
                    className="ui-button h-7 min-h-7 px-2 text-[11px]"
                    disabled={selectedHistoryIndex === displayedHistory.length - 1}
                    onClick={() => {
                      setIsPlaying(false);
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
            <div className={`mt-4 ${isSidebar ? "flex-1 min-h-0 overflow-y-auto pr-1" : ""}`}>
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
                        aria-current={isCurrent ? "step" : undefined}
                        onClick={() => {
                          setIsPlaying(false);
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
                        <div className="flex items-center justify-between gap-1">
                          <p className="truncate font-medium text-xs text-text">
                            <span className="mr-1.5 font-mono text-[11px] text-text-subtle">
                              {String(index + 1).padStart(2, "0")}
                            </span>
                            {actionLabel(event)}
                          </p>
                          <time className="shrink-0 font-mono text-[11px] text-text-subtle">
                            {formatTimestamp(event.at)}
                          </time>
                        </div>
                        <p className="mt-1 flex flex-wrap items-center gap-1 font-mono text-xs text-text-muted break-all">
                          <span>{event.fromPath ?? "Unknown"}</span>
                          <span className={`font-bold ${isFailed ? "text-warning" : "text-primary"}`}>
                            {isFailed ? "⇏" : "→"}
                          </span>
                          <span className={isFailed ? "line-through text-text-muted/60" : ""}>
                            {event.toPath ?? "Unknown"}
                          </span>
                          {isFailed && (
                            <span className="ml-1 rounded border border-warning-border bg-warning-subtle px-1 py-0.1 text-[10px] font-semibold text-warning">
                              Failed Attempt
                            </span>
                          )}
                        </p>
                        <div className="mt-1 flex items-center gap-1.5 text-[11px] text-text-subtle">
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
                          {event.sequence !== null ? <span>· event {event.sequence}</span> : null}
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
