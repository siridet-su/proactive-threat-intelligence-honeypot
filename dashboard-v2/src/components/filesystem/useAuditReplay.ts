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

  const selectedHistoryIndex = useMemo(() => {
    if (!displayedHistory.length) return -1;
    if (selectedHistoryEventId === null) return displayedHistory.length - 1;
    return displayedHistory.findIndex((event) => event.id === selectedHistoryEventId);
  }, [displayedHistory, selectedHistoryEventId]);

  const currentEvent = selectedHistoryIndex >= 0 ? displayedHistory[selectedHistoryIndex] : null;
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

  const activeHop: ActiveHopRoute | null = useMemo(
    () => deriveActiveHopRoute(displayedHistory, selectedHistoryIndex, displayedHistoryMetrics),
    [displayedHistory, displayedHistoryMetrics, selectedHistoryIndex],
  );

  const timeMetrics = useMemo(
    () => calculateHistoryTimeMetrics(displayedHistory, selectedHistoryIndex),
    [displayedHistory, selectedHistoryIndex],
  );

  const handlePrevHop = useCallback(() => {
    setIsPlaying(false);
    const nextId = calculateNextHistoryEventId(displayedHistory, selectedHistoryIndex, "prev");
    if (nextId) onSelectHistoryEventId(nextId);
  }, [displayedHistory, onSelectHistoryEventId, selectedHistoryIndex]);

  const handleNextHop = useCallback(() => {
    setIsPlaying(false);
    const nextId = calculateNextHistoryEventId(displayedHistory, selectedHistoryIndex, "next");
    if (nextId) onSelectHistoryEventId(nextId);
  }, [displayedHistory, onSelectHistoryEventId, selectedHistoryIndex]);

  const handleTogglePlay = useCallback(() => {
    if (selectedHistoryIndex >= displayedHistory.length - 1) {
      onSelectHistoryEventId(displayedHistory[0]?.id ?? null);
    }
    setIsPlaying((prev) => !prev);
  }, [displayedHistory, onSelectHistoryEventId, selectedHistoryIndex]);

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
    if (viewMode !== "audit" || !isPlaying) return;

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
    handlePrevHop,
    handleNextHop,
    handleTogglePlay,
    handlePause,
    handleToggleSpeed,
    handleTogglePacingMode,
  };
}
