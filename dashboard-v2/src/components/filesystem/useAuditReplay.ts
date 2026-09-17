"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  calculateHistoryTimeMetrics,
  calculateReplayPacingDelay,
  getHistoryWindowMetrics,
  type ActiveHopRoute,
  type HistoryWindowMetrics,
  type HopTimeMetrics,
  type ReplayPacingMode,
  type SessionReplayTimeSummary,
} from "./filesystemUtils";

export function deriveChronologicalHistory(history: readonly SessionCwdHistoryEvent[]): SessionCwdHistoryEvent[] {
  return [...history].reverse();
}

export function filterDisplayedHistory(
  chronologicalHistory: readonly SessionCwdHistoryEvent[],
  showFailedAttempts: boolean,
): SessionCwdHistoryEvent[] {
  if (showFailedAttempts) return [...chronologicalHistory];
  return chronologicalHistory.filter((e) => e.action !== "failed_change");
}

export function deriveActiveHopRoute(
  displayedHistory: readonly SessionCwdHistoryEvent[],
  selectedHistoryIndex: number,
  displayedHistoryMetrics: HistoryWindowMetrics,
): ActiveHopRoute | null {
  if (selectedHistoryIndex < 0 || !displayedHistory[selectedHistoryIndex]) return null;
  const currentEvent = displayedHistory[selectedHistoryIndex];
  const isFailed = currentEvent.action === "failed_change";
  const visitedStepMap: Record<string, number> = {};
  for (let i = 0; i <= selectedHistoryIndex; i++) {
    const ev = displayedHistory[i];
    if (ev.action !== "failed_change" && ev.toPath && visitedStepMap[ev.toPath] === undefined) {
      visitedStepMap[ev.toPath] = displayedHistoryMetrics.indexOffset + i + 1;
    }
  }
  return {
    eventId: currentEvent.id,
    fromPath: currentEvent.fromPath,
    toPath: isFailed ? currentEvent.fromPath : currentEvent.toPath,
    action: currentEvent.action,
    status: currentEvent.status,
    at: currentEvent.at,
    stepIndex: displayedHistoryMetrics.selectedNumber - 1,
    totalSteps: displayedHistoryMetrics.totalItems,
    visitedPaths: Object.keys(visitedStepMap),
    visitedStepMap,
    isFailedAttempt: isFailed,
  };
}

export function getNextPlaybackSpeed(currentSpeed: number): number {
  return currentSpeed === 1400 ? 700 : 1400;
}

export function getNextPacingMode(currentMode: ReplayPacingMode): ReplayPacingMode {
  return currentMode === "realistic" ? "uniform" : "realistic";
}

export function calculateNextHistoryEventId(
  displayedHistory: readonly SessionCwdHistoryEvent[],
  currentIndex: number,
  direction: "prev" | "next" | "loop",
): string | null {
  if (!displayedHistory.length) return null;
  if (direction === "prev") {
    if (currentIndex > 0) return displayedHistory[currentIndex - 1].id;
    return null;
  }
  if (direction === "next") {
    if (currentIndex >= 0 && currentIndex < displayedHistory.length - 1) {
      return displayedHistory[currentIndex + 1].id;
    }
    return null;
  }
  if (direction === "loop") {
    if (currentIndex >= displayedHistory.length - 1) {
      return displayedHistory[0].id;
    }
    return displayedHistory[currentIndex + 1]?.id ?? null;
  }
  return null;
}

export interface UseAuditReplayOptions {
  viewMode: "live" | "audit";
  history: SessionCwdHistoryEvent[];
  anchoredHop?: SessionCwdHistoryEvent | null;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  showFailedAttempts: boolean;
  selectedHistoryEventId: string | null;
  onSelectHistoryEventId: (id: string | null) => void;
  initialPacingMode?: ReplayPacingMode;
}

export interface UseAuditReplayReturn {
  isPlaying: boolean;
  setIsPlaying: React.Dispatch<React.SetStateAction<boolean>>;
  playbackSpeed: number;
  setPlaybackSpeed: React.Dispatch<React.SetStateAction<number>>;
  pacingMode: ReplayPacingMode;
  setPacingMode: React.Dispatch<React.SetStateAction<ReplayPacingMode>>;
  chronologicalHistory: SessionCwdHistoryEvent[];
  displayedHistory: SessionCwdHistoryEvent[];
  selectedHistoryIndex: number;
  displayedHistoryMetrics: HistoryWindowMetrics;
  activeHop: ActiveHopRoute | null;
  hopTimeMetrics: HopTimeMetrics[];
  sessionTimeSummary: SessionReplayTimeSummary;
  isAnchoredSelected: boolean;
  handlePrevHop: () => void;
  handleNextHop: () => void;
  handleTogglePlay: () => void;
  handlePause: () => void;
  handleToggleSpeed: () => void;
  handleTogglePacingMode: () => void;
}

export function useAuditReplay(options: UseAuditReplayOptions): UseAuditReplayReturn {
  const {
    viewMode,
    history,
    anchoredHop,
    historyTotalItems,
    historyTotalSuccessfulItems,
    showFailedAttempts,
    selectedHistoryEventId,
    onSelectHistoryEventId,
    initialPacingMode = "realistic",
  } = options;

  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1400);
  const [pacingMode, setPacingMode] = useState<ReplayPacingMode>(initialPacingMode);

  const chronologicalHistory = useMemo(() => deriveChronologicalHistory(history), [history]);

  const displayedHistory = useMemo(
    () => filterDisplayedHistory(chronologicalHistory, showFailedAttempts),
    [chronologicalHistory, showFailedAttempts],
  );

  const isAnchoredSelected = useMemo(() => {
    return Boolean(
      anchoredHop &&
      selectedHistoryEventId === anchoredHop.id &&
      !displayedHistory.some((event) => event.id === anchoredHop.id),
    );
  }, [anchoredHop, displayedHistory, selectedHistoryEventId]);

  const selectedHistoryIndex = useMemo(() => {
    if (isAnchoredSelected) return -1;
    if (!displayedHistory.length) return -1;
    if (selectedHistoryEventId === null) return displayedHistory.length - 1;
    return displayedHistory.findIndex((event) => event.id === selectedHistoryEventId);
  }, [displayedHistory, isAnchoredSelected, selectedHistoryEventId]);

  const currentEvent = isAnchoredSelected
    ? anchoredHop
    : selectedHistoryIndex >= 0
      ? displayedHistory[selectedHistoryIndex]
      : null;

  const explicitHopNumber = showFailedAttempts
    ? currentEvent?.hopNumber
    : currentEvent?.successfulHopNumber ?? currentEvent?.hopNumber;

  const displayedHistoryMetrics = useMemo(
    () =>
      getHistoryWindowMetrics(
        displayedHistory.length,
        showFailedAttempts ? historyTotalItems : historyTotalSuccessfulItems,
        selectedHistoryIndex,
        explicitHopNumber,
      ),
    [
      displayedHistory.length,
      historyTotalItems,
      historyTotalSuccessfulItems,
      selectedHistoryIndex,
      showFailedAttempts,
      explicitHopNumber,
    ],
  );

  const activeHop: ActiveHopRoute | null = useMemo(() => {
    if (isAnchoredSelected && anchoredHop) {
      const isFailed = anchoredHop.action === "failed_change";
      const hopNum = explicitHopNumber ?? 1;
      return {
        eventId: anchoredHop.id,
        fromPath: anchoredHop.fromPath,
        toPath: isFailed ? anchoredHop.fromPath : anchoredHop.toPath,
        action: anchoredHop.action,
        status: anchoredHop.status,
        at: anchoredHop.at,
        stepIndex: hopNum - 1,
        totalSteps: displayedHistoryMetrics.totalItems,
        visitedPaths: anchoredHop.toPath ? [anchoredHop.toPath] : [],
        visitedStepMap: anchoredHop.toPath ? { [anchoredHop.toPath]: hopNum } : {},
        isFailedAttempt: isFailed,
      };
    }
    return deriveActiveHopRoute(displayedHistory, selectedHistoryIndex, displayedHistoryMetrics);
  }, [
    anchoredHop,
    displayedHistory,
    displayedHistoryMetrics,
    explicitHopNumber,
    isAnchoredSelected,
    selectedHistoryIndex,
  ]);

  const timeMetrics = useMemo(() => {
    if (isAnchoredSelected && anchoredHop) {
      const hopNum = explicitHopNumber ?? 1;
      const progressPercent =
        displayedHistoryMetrics.totalItems > 0
          ? Math.min(100, Math.max(0, (hopNum / displayedHistoryMetrics.totalItems) * 100))
          : 0;
      return {
        hopMetrics: [],
        summary: {
          totalDurationMs: 0,
          formattedTotalDuration: "Partial",
          currentElapsedMs: 0,
          formattedCurrentElapsed: "+00:00",
          currentDeltaMs: 0,
          formattedCurrentDelta: "Gap",
          timeProgressPercent: progressPercent,
        },
      };
    }
    return calculateHistoryTimeMetrics(displayedHistory, selectedHistoryIndex);
  }, [
    anchoredHop,
    displayedHistory,
    displayedHistoryMetrics.totalItems,
    explicitHopNumber,
    isAnchoredSelected,
    selectedHistoryIndex,
  ]);

  const handlePrevHop = useCallback(() => {
    setIsPlaying(false);
    if (isAnchoredSelected) {
      // Cannot cross unloaded gap into unknown earlier events
      return;
    }
    const nextId = calculateNextHistoryEventId(displayedHistory, selectedHistoryIndex, "prev");
    if (nextId) onSelectHistoryEventId(nextId);
  }, [displayedHistory, isAnchoredSelected, onSelectHistoryEventId, selectedHistoryIndex]);

  const handleNextHop = useCallback(() => {
    setIsPlaying(false);
    if (isAnchoredSelected) {
      // Cannot cross unloaded gap into unknown later events
      return;
    }
    const nextId = calculateNextHistoryEventId(displayedHistory, selectedHistoryIndex, "next");
    if (nextId) onSelectHistoryEventId(nextId);
  }, [displayedHistory, isAnchoredSelected, onSelectHistoryEventId, selectedHistoryIndex]);

  const handleTogglePlay = useCallback(() => {
    if (isAnchoredSelected) {
      // Cannot auto-play across an unloaded gap
      return;
    }
    if (selectedHistoryIndex >= displayedHistory.length - 1) {
      onSelectHistoryEventId(displayedHistory[0]?.id ?? null);
    }
    setIsPlaying((prev) => !prev);
  }, [displayedHistory, isAnchoredSelected, onSelectHistoryEventId, selectedHistoryIndex]);

  const handlePause = useCallback(() => {
    setIsPlaying(false);
  }, []);

  const handleToggleSpeed = useCallback(() => {
    setPlaybackSpeed((current) => getNextPlaybackSpeed(current));
  }, []);

  const handleTogglePacingMode = useCallback(() => {
    setPacingMode((current) => getNextPacingMode(current));
  }, []);

  // Synchronized auto-play timer for audit mode with dynamic pacing support
  useEffect(() => {
    if (viewMode !== "audit" || !isPlaying || isAnchoredSelected) return;

    if (selectedHistoryIndex >= displayedHistory.length - 1) {
      return;
    }

    const nextIndex = selectedHistoryIndex + 1;
    const nextEvent = displayedHistory[nextIndex];
    if (!nextEvent) return;

    const nextMetric = timeMetrics.hopMetrics[nextIndex];
    const delay = calculateReplayPacingDelay(nextMetric?.deltaMs ?? 0, playbackSpeed, pacingMode);

    const timer = setTimeout(() => {
      onSelectHistoryEventId(nextEvent.id);
      if (nextIndex >= displayedHistory.length - 1) {
        setIsPlaying(false);
      }
    }, delay);

    return () => clearTimeout(timer);
  }, [
    viewMode,
    isPlaying,
    isAnchoredSelected,
    selectedHistoryIndex,
    displayedHistory,
    playbackSpeed,
    pacingMode,
    timeMetrics.hopMetrics,
    onSelectHistoryEventId,
  ]);

  return {
    isPlaying,
    setIsPlaying,
    playbackSpeed,
    setPlaybackSpeed,
    pacingMode,
    setPacingMode,
    chronologicalHistory,
    displayedHistory,
    selectedHistoryIndex,
    displayedHistoryMetrics,
    activeHop,
    hopTimeMetrics: timeMetrics.hopMetrics,
    sessionTimeSummary: timeMetrics.summary,
    isAnchoredSelected,
    handlePrevHop,
    handleNextHop,
    handleTogglePlay,
    handlePause,
    handleToggleSpeed,
    handleTogglePacingMode,
  };
}
