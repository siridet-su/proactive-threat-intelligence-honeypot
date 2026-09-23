import { AlertTriangle, ChevronLeft, ChevronRight, Clock, CornerDownRight, FastForward, Pause, Play, Rewind } from "lucide-react";
import type { KeyboardEvent } from "react";

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatElapsedTime, formatFailedChangeMessage, formatFromPath, isInitialSshEntry, mapReplayTimelineValueToIndex } from "./filesystemUtils";

export interface ReplayTransportProps {
  isAnchoredSelected: boolean;
  historyComplete: boolean;
  onLoadEarlier: () => void;
  selectedHistoryIndex: number;
  displayedHistoryLength: number;
  selectDisplayedHistoryIndex: (index: number) => void;
  handleTogglePlay: () => void;
  isPlaying: boolean;
  onToggleSpeed: () => void;
  playbackSpeed: number;
  onTogglePacingMode: () => void;
  pacingMode: string;
  failedCount: number;
  showFailedAttempts: boolean;
  onToggleShowFailedAttempts: (show: boolean) => void;
  displayedHistoryMetrics: {
    selectedNumber: number;
    totalItems: number;
  };
  timeMetrics: {
    summary: {
      formattedCurrentElapsed: string;
      formattedTotalDuration: string;
      formattedCurrentDelta: string;
      timeProgressPercent: number;
      totalDurationMs: number;
    };
  };
  replayTimeline: import("./filesystemUtils").ReplayTimeline;
  handleScrubberKeyDown: (e: KeyboardEvent<HTMLInputElement>) => void;
  isFailedHop: boolean;
  selectedHistoryEvent: SessionCwdHistoryEvent | null;
}

export function ReplayTransport({
  isAnchoredSelected,
  selectedHistoryIndex,
  displayedHistoryLength,
  selectDisplayedHistoryIndex,
  handleTogglePlay,
  isPlaying,
  onToggleSpeed,
  playbackSpeed,
  onTogglePacingMode,
  pacingMode,
  failedCount,
  showFailedAttempts,
  onToggleShowFailedAttempts,
  displayedHistoryMetrics,
  timeMetrics,
  replayTimeline,
  handleScrubberKeyDown,
  isFailedHop,
  selectedHistoryEvent,
}: ReplayTransportProps) {
  const fromPathStr = selectedHistoryEvent && isInitialSshEntry(selectedHistoryEvent) ? "[SSH Login]" : selectedHistoryEvent ? formatFromPath(selectedHistoryEvent) : "";
  const toPathStr = selectedHistoryEvent?.toPath ?? "Unknown";

  return (
    <div className="sticky top-0 z-10 rounded-xl border border-border bg-surface p-3 shadow-md space-y-3" aria-live="polite">
      {isAnchoredSelected && (
        <div
          role="note"
          className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200/90 shadow-xs"
        >
          <div className="flex items-center gap-2 font-medium">
            <span className="rounded bg-amber-500/20 px-1.5 py-0.5 uppercase tracking-wide text-amber-300">
              Anchored
            </span>
            <span>Anchored deep hop: intervening events are unloaded. Replay and adjacent stepping are paused across this gap.</span>
          </div>
        </div>
      )}

      {/* Header: Action & Paths */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 min-w-0">
          {isFailedHop ? (
            <AlertTriangle className="h-4 w-4 text-warning shrink-0" />
          ) : (
            <CornerDownRight className="h-4 w-4 text-primary shrink-0" />
          )}
          {isFailedHop ? (
            <span
              role="status"
              data-testid="failed-change-transport-status"
              aria-label={formatFailedChangeMessage(selectedHistoryEvent?.fromPath)}
              className="text-sm font-semibold text-warning"
            >
              {formatFailedChangeMessage(selectedHistoryEvent?.fromPath)}
            </span>
          ) : (
            <span className="text-sm font-semibold truncate text-text">
              <span className="text-text-subtle font-normal mr-1.5">from</span>
              <span className="text-text-muted" title={fromPathStr || undefined}>{fromPathStr}</span>
              <span className="text-text-subtle font-normal mx-1.5">to</span>
              <span className="text-text" title={toPathStr}>{toPathStr}</span>
            </span>
          )}
        </div>
        <span className={`text-xs px-2 py-1 rounded-md font-medium shrink-0 shadow-2xs ${
          isFailedHop ? 'bg-warning-subtle text-warning border border-warning-border' : 'bg-surface-subtle border border-border text-text'
        }`}>
          {isFailedHop ? "Failed" : (selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "")}
        </span>
      </div>

      {/* Scrubber Area */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-xs font-mono text-text-muted px-1">
          <span>{timeMetrics.summary.formattedCurrentElapsed}</span>
          <span className="text-text-subtle font-sans font-medium px-2 truncate">
            {selectedHistoryIndex === 0
              ? "Initial entry"
              : `Dwell: +${timeMetrics.summary.formattedCurrentDelta}`}
          </span>
          <span title={timeMetrics.summary.formattedTotalDuration}>
            <span className="sr-only">{timeMetrics.summary.formattedTotalDuration}</span>
            <span aria-hidden="true">{formatElapsedTime(timeMetrics.summary.totalDurationMs)}</span>
          </span>
        </div>

        {/* Scrub slider */}
        <div className="relative flex items-center group">
          <input
            type="range"
            min={0}
            max={replayTimeline.maxValue}
            step={1}
            value={replayTimeline.value}
            disabled={isAnchoredSelected || displayedHistoryLength <= 1}
            onKeyDown={handleScrubberKeyDown}
            onChange={(e) => {
              const targetIndex = mapReplayTimelineValueToIndex(replayTimeline, Number(e.target.value));
              if (targetIndex !== null) {
                selectDisplayedHistoryIndex(targetIndex);
              }
            }}
            aria-label="Replay timeline scrubber"
            aria-valuemin={replayTimeline.minValue}
            aria-valuemax={replayTimeline.maxValue}
            aria-valuenow={replayTimeline.value}
            aria-valuetext={
              isAnchoredSelected
                ? `Hop ${displayedHistoryMetrics.selectedNumber} of ${displayedHistoryMetrics.totalItems} (Anchored deep target, replay scrubber paused across unloaded gap)`
                : `${replayTimeline.timingLabel}; ${replayTimeline.durationLabel}; Hop ${displayedHistoryMetrics.selectedNumber} of ${displayedHistoryMetrics.totalItems}, elapsed ${timeMetrics.summary.formattedCurrentElapsed}, dwell ${timeMetrics.summary.formattedCurrentDelta}`
            }
            className="w-full h-2 bg-border/60 rounded-lg appearance-none cursor-pointer accent-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:opacity-40 disabled:cursor-not-allowed group-hover:bg-border transition-colors"
          />
        </div>
      </div>

      {/* Controls Row */}
      {/* Controls Area */}
      <div className="flex flex-col gap-2.5 pt-2">
        {/* Playback Controls (Row 1) */}
        <div className="flex justify-center">
          <div className="flex items-center rounded-lg border border-border bg-surface shadow-xs p-0.5">
            <button
              type="button"
              className="h-8 w-10 flex items-center justify-center shrink-0 text-text-muted hover:text-text hover:bg-surface-hover rounded-md transition-colors disabled:opacity-40 disabled:hover:bg-transparent"
              title="Jump to first hop"
              aria-label="First hop"
              data-keyboard-tooltip
              disabled={!isAnchoredSelected && selectedHistoryIndex === 0}
              onClick={() => selectDisplayedHistoryIndex(0)}
            >
              <Rewind className="h-4 w-4" />
            </button>
            <button
              type="button"
              className="h-8 w-10 flex items-center justify-center shrink-0 text-text-muted hover:text-text hover:bg-surface-hover rounded-md transition-colors disabled:opacity-40 disabled:hover:bg-transparent"
              title="Previous hop"
              aria-label="Previous hop"
              data-keyboard-tooltip
              disabled={!isAnchoredSelected && selectedHistoryIndex === 0}
              onClick={() => selectDisplayedHistoryIndex(Math.max(0, selectedHistoryIndex - 1))}
            >
              <ChevronLeft className="h-4 w-4" />
            </button>

            <div className="w-px h-5 bg-border/60 mx-1" />

            <button
              type="button"
              className={`h-8 px-4 flex items-center justify-center gap-1.5 shrink-0 font-medium rounded-md transition-colors disabled:opacity-40 ${
                isPlaying
                  ? "bg-amber-500/10 text-amber-500 hover:bg-amber-500/20"
                  : "bg-primary/10 text-primary hover:bg-primary/20"
              }`}
              onClick={handleTogglePlay}
              disabled={isAnchoredSelected}
              aria-label={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? (
                <>
                  <Pause className="h-4 w-4 fill-current" />
                  <span className="text-xs">Pause</span>
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 fill-current ml-0.5" />
                  <span className="text-xs">Play</span>
                </>
              )}
            </button>

            <div className="w-px h-5 bg-border/60 mx-1" />

            <button
              type="button"
              className="h-8 w-10 flex items-center justify-center shrink-0 text-text-muted hover:text-text hover:bg-surface-hover rounded-md transition-colors disabled:opacity-40 disabled:hover:bg-transparent"
              title="Next hop"
              aria-label="Next hop"
              data-keyboard-tooltip
              disabled={!isAnchoredSelected && selectedHistoryIndex === displayedHistoryLength - 1}
              onClick={() => selectDisplayedHistoryIndex(Math.min(displayedHistoryLength - 1, selectedHistoryIndex + 1))}
            >
              <ChevronRight className="h-4 w-4" />
            </button>
            <button
              type="button"
              className="h-8 w-10 flex items-center justify-center shrink-0 text-text-muted hover:text-text hover:bg-surface-hover rounded-md transition-colors disabled:opacity-40 disabled:hover:bg-transparent"
              title="Jump to latest hop"
              aria-label="Latest hop"
              data-keyboard-tooltip
              disabled={!isAnchoredSelected && selectedHistoryIndex === displayedHistoryLength - 1}
              onClick={() => selectDisplayedHistoryIndex(displayedHistoryLength - 1)}
            >
              <FastForward className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Tools & Metadata (Row 2) */}
        <div className="flex items-center justify-between min-w-0">
          <div className="flex items-center rounded-lg border border-border bg-surface-subtle p-0.5 shrink-0">
            <button
              type="button"
              onClick={onToggleSpeed}
              className="px-2 h-7 rounded-md text-xs font-mono font-medium hover:bg-surface-hover hover:text-text transition-colors text-text-muted"
              title="Toggle playback speed (1x / 2x)"
            >
              {playbackSpeed === 1400 ? "1x" : "2x"}
            </button>
            <div className="w-px h-3.5 bg-border mx-0.5" />
            <button
              type="button"
              onClick={onTogglePacingMode}
              className={`px-2 h-7 rounded-md text-xs flex items-center gap-1.5 font-medium transition-colors ${
                pacingMode === "realistic" ? "text-primary bg-primary/5 shadow-2xs" : "hover:bg-surface-hover hover:text-text text-text-muted"
              }`}
              title={`Playback pacing: ${
                pacingMode === "realistic"
                  ? "Realistic (proportional delay based on real attacker dwell time)"
                  : "Step (uniform fixed interval)"
              }`}
            >
              <Clock className="h-3 w-3" />
              <span>{pacingMode === "realistic" ? "Real" : "Step"}</span>
            </button>
          </div>

          <div className="flex items-center gap-2 pl-2 shrink-0">
            {failedCount > 0 && (
              <label className="flex items-center gap-1.5 text-xs text-text-subtle cursor-pointer select-none border border-transparent hover:border-border/50 px-1.5 py-1 rounded transition-colors">
                <input
                  type="checkbox"
                  checked={showFailedAttempts}
                  onChange={(e) => onToggleShowFailedAttempts(e.target.checked)}
                  className="h-3 w-3 rounded border-border text-primary focus:ring-primary"
                />
                <span>Fail ({failedCount})</span>
              </label>
            )}

            <div className="text-xs font-mono text-text-subtle bg-surface-subtle border border-border/50 px-2.5 py-1 rounded-md shadow-xs">
              Hop <span className="text-text font-medium">{displayedHistoryMetrics.selectedNumber}</span>/{displayedHistoryMetrics.totalItems}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
