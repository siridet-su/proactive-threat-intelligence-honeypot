import { AlertTriangle, ChevronLeft, ChevronRight, Clock, CornerDownRight, FastForward, Pause, Play, Rewind } from "lucide-react";
import type { KeyboardEvent } from "react";

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatElapsedTime, formatFromPath, isInitialSshEntry, mapReplayTimelineValueToIndex } from "./filesystemUtils";

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
  historyComplete,
  onLoadEarlier,
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
  return (
    <div className="sticky top-0 z-10 rounded-xl border border-border bg-surface-subtle p-2.5 shadow-2xs" aria-live="polite">
      {isAnchoredSelected && (
        <div
          role="note"
          className="mb-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-200"
          data-testid="anchored-hop-banner"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span>Anchored deep hop: intervening events are unloaded. Replay and adjacent stepping are paused across this gap.</span>
            {!historyComplete && (
              <button
                type="button"
                onClick={onLoadEarlier}
                className="shrink-0 rounded bg-amber-500/20 px-2 py-0.5 font-medium text-amber-100 hover:bg-amber-500/30 transition-colors text-[11px]"
              >
                Load earlier hops
              </button>
            )}
          </div>
        </div>
      )}

      {/* Controls & Scrubber Row */}
      <div className="flex items-center justify-between gap-1.5">
        <div className="flex items-center gap-1">
          <button
            type="button"
            className="ui-button h-9 w-9 p-0 shrink-0"
            title="Jump to first hop"
            aria-label="First hop"
            disabled={isAnchoredSelected || selectedHistoryIndex <= 0}
            onClick={() => {
              selectDisplayedHistoryIndex(0);
            }}
          >
            <Rewind className="h-3 w-3" />
          </button>

          <button
            type="button"
            className="ui-button h-9 w-9 p-0 shrink-0"
            title="Previous hop"
            aria-label="Previous hop"
            disabled={isAnchoredSelected || selectedHistoryIndex <= 0}
            onClick={() => {
              selectDisplayedHistoryIndex(selectedHistoryIndex - 1);
            }}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={handleTogglePlay}
            disabled={isAnchoredSelected}
            className={`ui-button h-9 min-h-9 px-2.5 text-xs flex items-center gap-1 shrink-0 ${
              isPlaying ? "border-primary bg-primary text-surface" : ""
            } ${isAnchoredSelected ? "opacity-40 cursor-not-allowed" : ""}`}
            title={isPlaying ? "Pause playback" : "Play route trajectory"}
            aria-label={isPlaying ? "Pause" : "Play"}
          >
            {isPlaying ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
            <span>{isPlaying ? "Pause" : "Play"}</span>
          </button>

          <button
            type="button"
            className="ui-button h-9 w-9 p-0 shrink-0"
            title="Next hop"
            aria-label="Next hop"
            disabled={isAnchoredSelected || selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistoryLength - 1}
            onClick={() => {
              selectDisplayedHistoryIndex(selectedHistoryIndex + 1);
            }}
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            className="ui-button h-9 w-9 p-0 shrink-0"
            title="Jump to latest hop"
            aria-label="Latest hop"
            disabled={!isAnchoredSelected && selectedHistoryIndex === displayedHistoryLength - 1}
            onClick={() => {
              selectDisplayedHistoryIndex(displayedHistoryLength - 1);
            }}
          >
            <FastForward className="h-3 w-3" />
          </button>

          <button
            type="button"
            onClick={onToggleSpeed}
            className="ui-button h-9 min-h-9 px-2 font-mono text-xs shrink-0"
            title="Toggle playback speed (1x / 2x)"
          >
            {playbackSpeed === 1400 ? "1x" : "2x"}
          </button>

          <button
            type="button"
            onClick={onTogglePacingMode}
            className={`ui-button h-9 min-h-9 px-2 font-mono text-xs shrink-0 flex items-center gap-1 ${
              pacingMode === "realistic" ? "border-primary/50 text-primary" : ""
            }`}
            title={`Playback pacing: ${
              pacingMode === "realistic"
                ? "Realistic (proportional delay based on real attacker dwell time)"
                : "Step (uniform fixed interval)"
            }`}
            aria-label={`Playback pacing mode: ${pacingMode}`}
          >
            <Clock className="h-3 w-3" />
            <span>{pacingMode === "realistic" ? "Real" : "Step"}</span>
          </button>
        </div>

        {/* Right side: Failures + Hop indicator */}
        <div className="flex items-center gap-2">
          {failedCount > 0 && (
            <label className="flex items-center gap-1 text-xs text-text-subtle cursor-pointer select-none whitespace-nowrap shrink-0">
              <input
                type="checkbox"
                checked={showFailedAttempts}
                onChange={(e) => {
                  onToggleShowFailedAttempts(e.target.checked);
                }}
                className="h-4 w-4 rounded border-border text-primary focus:ring-primary"
              />
              <span>Failures ({failedCount})</span>
            </label>
          )}

          <span className="rounded-full bg-surface px-2 py-0.5 font-mono text-xs font-semibold text-primary border border-primary-border shrink-0 flex items-center gap-1">
            <span>Hop {displayedHistoryMetrics.selectedNumber}/{displayedHistoryMetrics.totalItems}</span>
            {isAnchoredSelected && (
              <span className="rounded bg-amber-500/20 px-1 py-0.2 text-[9px] uppercase font-bold text-amber-300">
                Anchored
              </span>
            )}
          </span>
        </div>
      </div>

      {/* Interactive Time Scrubber Slider */}
      <div className="mt-2.5 px-0.5">
        <div className="flex items-center justify-between gap-2 text-xs font-mono text-text-subtle mb-1">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3 text-text-muted" aria-hidden="true" />
            <span className="text-text font-medium">{timeMetrics.summary.formattedCurrentElapsed}</span>
            <span className="text-text-muted/60">/</span>
            <span title={timeMetrics.summary.formattedTotalDuration}>
              <span className="sr-only">{timeMetrics.summary.formattedTotalDuration}</span>
              <span aria-hidden="true">{formatElapsedTime(timeMetrics.summary.totalDurationMs)}</span>
            </span>
          </span>
          <span className="truncate ml-2">
            {selectedHistoryIndex === 0
              ? "Initial entry"
              : `Dwell: +${timeMetrics.summary.formattedCurrentDelta}`}
          </span>
        </div>

        {/* Scrub slider */}
        <div className="relative flex items-center">
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
            className="w-full h-1.5 bg-border/60 rounded-lg appearance-none cursor-pointer accent-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:opacity-40 disabled:cursor-not-allowed"
          />
        </div>
      </div>

      {/* Transition Summary Bar & Progress */}
      <div
        className={`mt-2 rounded-lg border px-2.5 py-1.5 transition-colors overflow-hidden ${
          isFailedHop
            ? "border-warning-border bg-warning-subtle text-text"
            : "border-primary-border bg-primary-subtle text-text"
        }`}
      >
        <div className="flex items-center justify-between gap-2 font-mono text-xs">
          <div className="flex items-center gap-1.5 truncate min-w-0">
            {isFailedHop ? (
              <AlertTriangle className="h-3.5 w-3.5 text-warning shrink-0" />
            ) : (
              <CornerDownRight className="h-3.5 w-3.5 text-primary shrink-0" />
            )}
            <span className="text-xs text-text-subtle truncate max-w-[120px]" title={selectedHistoryEvent?.fromPath ?? undefined}>
              {selectedHistoryEvent && isInitialSshEntry(selectedHistoryEvent) ? "[SSH Login]" : selectedHistoryEvent ? formatFromPath(selectedHistoryEvent) : ""}
            </span>
            <span className="text-text-subtle">→</span>
            <strong className={`truncate ${isFailedHop ? "line-through text-warning" : "text-text"}`} title={selectedHistoryEvent?.toPath ?? undefined}>
              {selectedHistoryEvent?.toPath ?? "Unknown"}
            </strong>
          </div>

          <span className="text-xs font-sans text-text-subtle shrink-0">
            {isFailedHop ? "Failed" : (selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "")}
          </span>
        </div>

        {/* Dual Progress bar: Step progress + Time progress */}
        <div
          className="mt-1.5 relative h-1.5 w-full rounded-full bg-border/40 overflow-hidden"
          title={`Time elapsed: ${Math.round(timeMetrics.summary.timeProgressPercent)}% | Hop: ${displayedHistoryMetrics.selectedNumber}/${displayedHistoryMetrics.totalItems}`}
        >
          <div
            className="absolute inset-y-0 left-0 bg-primary/25 transition-all duration-200"
            style={{ width: `${timeMetrics.summary.timeProgressPercent}%` }}
          />
          <div
            className={`relative h-full rounded-full transition-all duration-200 ${
              isFailedHop ? "bg-warning" : "bg-primary"
            }`}
            style={{
              width: `${
                displayedHistoryMetrics.totalItems > 0
                  ? Math.min(100, Math.max(0, (displayedHistoryMetrics.selectedNumber / displayedHistoryMetrics.totalItems) * 100))
                  : 0
              }%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}
