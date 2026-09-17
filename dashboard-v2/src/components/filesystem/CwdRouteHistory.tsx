"use client";

import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  CornerDownRight,
  FastForward,
  History,
  Pause,
  Play,
  Power,
  Plus,
  RefreshCw,
  Rewind,
  Shield,
  Terminal,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  actionLabel,
  calculateHistoryTimeMetrics,
  calculateReplayPacingDelay,
  formatFromPath,
  formatTimestamp,
  getHistoryWindowMetrics,
  isInitialSshEntry,
  statusLabel,
  type ReplayPacingMode,
} from "./filesystemUtils";
import { useResponseAction } from "./useResponseAction";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { OperationToast } from "@/components/ui/OperationToast";
import type { HopResolutionStatus } from "./sessionHopResolver";

type SidebarTab = "replay" | "commands" | "actions";

const SIDEBAR_TAB_COLUMN: Record<SidebarTab, number> = {
  replay: 1,
  commands: 2,
  actions: 3,
};

const SIDEBAR_CONTENT_VARIANTS = {
  enter: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * 10 }),
  center: { opacity: 1, x: 0 },
  exit: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * -6 }),
};

interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  anchoredHop?: SessionCwdHistoryEvent | null;
  historyStatus: RegionStatus;
  historyCursor: string | null;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  historyComplete: boolean;
  selectedHistoryEventId: string | null;
  layout?: "card" | "sidebar";
  sessionIsLive?: boolean;
  hopResolutionStatus?: HopResolutionStatus;
  requestedHop?: string | null;
  onClearHop?: () => void;
  onShowLatestHop?: () => void;
  onSelectHistoryEventId: (eventId: string | null, source?: "user" | "playback" | "sync") => void;
  onLoadEarlier: () => void;
  isPlaying?: boolean;
  onTogglePlay?: () => void;
  onPause?: () => void;
  playbackSpeed?: number;
  onToggleSpeed?: () => void;
  pacingMode?: ReplayPacingMode;
  onTogglePacingMode?: () => void;
  showFailedAttempts?: boolean;
  onToggleShowFailedAttempts?: (show: boolean) => void;
}

export function CwdRouteHistory({
  selectedSession,
  history,
  anchoredHop = null,
  historyStatus,
  historyCursor,
  historyTotalItems,
  historyTotalSuccessfulItems,
  historyComplete,
  selectedHistoryEventId,
  layout = "card",
  sessionIsLive = false,
  hopResolutionStatus = "idle",
  requestedHop = null,
  onClearHop,
  onShowLatestHop,
  onSelectHistoryEventId,
  onLoadEarlier,
  isPlaying: controlledIsPlaying,
  onTogglePlay,
  onPause,
  playbackSpeed: controlledPlaybackSpeed,
  onToggleSpeed,
  pacingMode: controlledPacingMode,
  onTogglePacingMode,
  showFailedAttempts: controlledShowFailedAttempts,
  onToggleShowFailedAttempts,
}: CwdRouteHistoryProps) {
  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);
  const [internalIsPlaying, setInternalIsPlaying] = useState(false);
  const [internalPlaybackSpeed, setInternalPlaybackSpeed] = useState<number>(1400);
  const [internalPacingMode, setInternalPacingMode] = useState<ReplayPacingMode>("realistic");
  const [internalShowFailedAttempts, setInternalShowFailedAttempts] = useState(true);
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("replay");
  const [sidebarTabDirection, setSidebarTabDirection] = useState(1);
  const shouldReduceMotion = useReducedMotion();
  const isSidebar = layout === "sidebar";

  const {
    visibleTerminateAction,
    visibleTerminateCapability,
    terminateDialogOpen,
    setTerminateDialogOpen,
    terminateProcessing,
    terminateError,
    setTerminateError,
    operationToast,
    setOperationToast,
    handleTerminateSession,
  } = useResponseAction({
    selectedSession,
    sessionIsLive,
    enabled: isSidebar && sidebarTab === "actions",
  });

  const isPlaying = controlledIsPlaying !== undefined ? controlledIsPlaying : internalIsPlaying;
  const playbackSpeed = controlledPlaybackSpeed !== undefined ? controlledPlaybackSpeed : internalPlaybackSpeed;
  const pacingMode = controlledPacingMode !== undefined ? controlledPacingMode : internalPacingMode;
  const showFailedAttempts = controlledShowFailedAttempts !== undefined ? controlledShowFailedAttempts : internalShowFailedAttempts;

  const failedCount = Math.max(0, historyTotalItems - historyTotalSuccessfulItems);

  const displayedHistory = useMemo(() => {
    if (showFailedAttempts) return chronologicalHistory;
    return chronologicalHistory.filter((e) => e.action !== "failed_change");
  }, [chronologicalHistory, showFailedAttempts]);

  const isAnchoredSelected = Boolean(
    anchoredHop &&
    selectedHistoryEventId === anchoredHop.id &&
    !displayedHistory.some((event) => event.id === anchoredHop.id),
  );

  const selectedHistoryIndex = useMemo(() => {
    if (isAnchoredSelected) return -1;
    if (!displayedHistory.length) return -1;
    if (selectedHistoryEventId === null) return displayedHistory.length - 1;
    const index = displayedHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : displayedHistory.length - 1;
  }, [displayedHistory, isAnchoredSelected, selectedHistoryEventId]);

  const selectedHistoryEvent = isAnchoredSelected
    ? anchoredHop
    : selectedHistoryIndex >= 0
      ? displayedHistory[selectedHistoryIndex]
      : null;

  const explicitHopNumber = showFailedAttempts
    ? selectedHistoryEvent?.hopNumber
    : (selectedHistoryEvent?.successfulHopNumber ?? selectedHistoryEvent?.hopNumber);

  const displayedHistoryMetrics = useMemo(
    () => getHistoryWindowMetrics(
      displayedHistory.length,
      showFailedAttempts ? historyTotalItems : historyTotalSuccessfulItems,
      selectedHistoryIndex,
      explicitHopNumber,
    ),
    [displayedHistory.length, historyTotalItems, historyTotalSuccessfulItems, selectedHistoryIndex, showFailedAttempts, explicitHopNumber],
  );

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
  }, [displayedHistory, selectedHistoryIndex, isAnchoredSelected, anchoredHop, explicitHopNumber, displayedHistoryMetrics.totalItems]);

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

  // Auto-play timer with dynamic realistic pacing (only active if not controlled externally by parent)
  useEffect(() => {
    if (controlledIsPlaying !== undefined) return;
    if (!isPlaying) return;

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
        setInternalIsPlaying(false);
      }
    }, delay);

    return () => clearTimeout(timer);
  }, [
    controlledIsPlaying,
    isPlaying,
    selectedHistoryIndex,
    displayedHistory,
    playbackSpeed,
    pacingMode,
    timeMetrics.hopMetrics,
    onSelectHistoryEventId,
  ]);

  const sidebarTabColumn = SIDEBAR_TAB_COLUMN[sidebarTab];
  const sidebarContentDirection = shouldReduceMotion ? 0 : sidebarTabDirection;

  const handleSidebarTabChange = (nextTab: SidebarTab) => {
    if (nextTab === sidebarTab) return;
    setSidebarTabDirection(SIDEBAR_TAB_COLUMN[nextTab] > sidebarTabColumn ? 1 : -1);
    setSidebarTab(nextTab);
  };

  return (
    <div className={`ui-panel overflow-hidden ${isSidebar ? "flex flex-col h-full min-h-0" : ""}`}>
      {/* Panel Header with Compact Tabs */}
      <div
        className={`flex shrink-0 gap-2 border-b border-border px-3.5 py-2.5 ${
          isSidebar ? "flex-col" : "flex-col sm:flex-row sm:items-center sm:justify-between"
        }`}
      >
        <div className={`min-w-0 ${isSidebar ? "flex flex-col gap-2" : "flex items-center gap-2"}`}>
          <div className="flex min-w-0 items-center gap-2">
            <History className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="truncate text-xs font-semibold sm:text-sm">
              {isSidebar ? "Forensic Studio" : "Verified CWD route"}
            </h2>
          </div>
          {isSidebar && (
            <div
              className="relative isolate grid w-full grid-cols-3 gap-1 rounded-lg border border-border bg-surface-subtle p-0.5 text-xs"
              aria-label="Forensic studio views"
            >
              <div aria-hidden="true" className="pointer-events-none absolute inset-0.5 grid grid-cols-3 gap-1">
                <motion.span
                  layout="position"
                  data-forensic-tab-highlight
                  className="rounded-md border border-border bg-surface shadow-2xs"
                  style={{ gridColumnStart: sidebarTabColumn }}
                  transition={
                    shouldReduceMotion
                      ? { duration: 0 }
                      : { duration: 0.28, ease: [0.4, 0, 0.2, 1] }
                  }
                />
              </div>
              {([
                { id: "replay", label: "Route Replay", icon: null },
                { id: "commands", label: "Command data", icon: Terminal },
                { id: "actions", label: "Response", icon: Shield },
              ] as const).map((tab) => {
                const isActive = sidebarTab === tab.id;
                const Icon = tab.icon;

                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => handleSidebarTabChange(tab.id)}
                    aria-pressed={isActive}
                    className={`relative z-10 flex min-h-9 cursor-pointer items-center justify-center gap-1 rounded-md border border-transparent px-2 text-xs font-medium transition-colors duration-300 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring ${
                      isActive ? "text-primary" : "text-text-muted hover:text-text"
                    }`}
                  >
                    {Icon && <Icon className="h-3 w-3" aria-hidden="true" />}
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        {selectedSession && !isSidebar && (
          <span className="ui-badge shrink-0 font-mono text-xs whitespace-nowrap hidden sm:inline-flex py-0.5 px-2">
            {selectedSession.sessionId.slice(0, 8)}…
          </span>
        )}
      </div>

      <div className={`p-3 ${isSidebar ? "flex flex-1 flex-col min-h-0 overflow-hidden" : ""}`}>
        {!selectedSession ? (
          <RegionState
            kind="empty"
            title="Select a session to inspect its path history"
            description="Choose a session from the topology or inspector."
          />
        ) : (
          <>
            {/* Hop resolution feedback alert for unavailable, missing, or cross-session hops */}
            {(hopResolutionStatus === "not-found" || hopResolutionStatus === "error") && (
              <div
                role="alert"
                className="mb-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200"
                data-testid="hop-resolution-banner"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <p className="font-semibold text-amber-100">
                      {hopResolutionStatus === "not-found"
                        ? "Requested hop unavailable"
                        : "Error resolving requested hop"}
                    </p>
                    <p className="mt-0.5 text-amber-200/80">
                      {hopResolutionStatus === "not-found"
                        ? `The requested hop "${requestedHop}" could not be found or has expired.`
                        : `Could not retrieve hop "${requestedHop}".`}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    {onShowLatestHop && history.length > 0 && (
                      <button
                        type="button"
                        onClick={onShowLatestHop}
                        className="rounded bg-amber-500/20 px-2.5 py-1 font-medium text-amber-100 hover:bg-amber-500/30 transition-colors"
                      >
                        Show latest hop
                      </button>
                    )}
                    {onClearHop && (
                      <button
                        type="button"
                        onClick={onClearHop}
                        className="rounded border border-amber-500/40 px-2.5 py-1 font-medium text-amber-200 hover:bg-amber-500/20 transition-colors"
                      >
                        Clear hop
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            {!isSidebar && historyStatus === "error" && !history.length ? (
              <RegionState
                kind="error"
                title="Session history unavailable"
                description="The selected CWD history could not be loaded."
              />
            ) : !isSidebar && historyStatus === "loading" && !history.length ? (
              <RegionState kind="loading" title="Loading session history" />
            ) : !isSidebar && !history.length ? (
              <RegionState
                kind="empty"
                title="No verified directory transitions"
                description="This session has a known observed path, but Cowrie has not recorded a directory move. It may have ended after a non-interactive probe."
              />
            ) : (
              <AnimatePresence initial={false} mode="popLayout" custom={sidebarContentDirection}>
            <motion.div
              key={isSidebar ? sidebarTab : "route-history"}
              data-forensic-tab-panel={sidebarTab}
              custom={sidebarContentDirection}
              variants={SIDEBAR_CONTENT_VARIANTS}
              initial={isSidebar ? "enter" : false}
              animate="center"
              exit={isSidebar ? "exit" : undefined}
              transition={
                shouldReduceMotion
                  ? { duration: 0 }
                  : { duration: 0.18, ease: [0.4, 0, 0.2, 1] }
              }
              className={isSidebar ? "flex min-h-0 flex-1 flex-col" : undefined}
            >
              {sidebarTab === "commands" ? (
                /* Command telemetry is intentionally explicit when no authoritative feed is connected. */
                <div className="flex flex-1 flex-col min-h-0 space-y-3">
            <div className="rounded-xl border border-border bg-surface-subtle p-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="text-text-muted">Selected CWD context</span>
                <span className="font-mono text-text">
                  {selectedHistoryEvent?.toPath ?? selectedSession.cwdState.path ?? "Unknown"}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2 text-xs text-text-subtle">
                <span>
                  {selectedHistoryEvent
                    ? `Hop ${displayedHistoryMetrics.selectedNumber} of ${displayedHistoryMetrics.totalItems}`
                    : "No route hop recorded"}
                </span>
                <span>{formatTimestamp(selectedHistoryEvent?.at ?? selectedSession.cwdState.observedAt)}</span>
              </div>
            </div>
            <RegionState
              kind="empty"
              title="Command and file telemetry unavailable"
              description="No authoritative command, payload, or file event is linked to this CWD hop. Only verified directory transitions are shown."
            />
                </div>
              ) : sidebarTab === "actions" ? (
                <div className="flex flex-1 flex-col min-h-0 space-y-3">
            <div className="rounded-xl border border-border bg-surface-subtle p-3 space-y-2.5">
              <div className="text-xs font-semibold text-text">Selected session</div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="rounded bg-surface p-2 border border-border">
                  <div className="text-xs text-text-subtle">Source IP</div>
                  <div className="font-semibold text-text mt-0.5 truncate">{selectedSession.sourceIp}</div>
                </div>
                <div className="rounded bg-surface p-2 border border-border">
                  <div className="text-xs text-text-subtle">Session ID</div>
                  <div className="font-bold text-text mt-0.5 truncate">{selectedSession.sessionId.slice(0, 10)}…</div>
                </div>
              </div>
            </div>
            {visibleTerminateAction && (
              <div className={`rounded-xl border p-3 ${visibleTerminateAction.status === "verified" ? "border-success-border bg-success-subtle" : visibleTerminateAction.status === "failed" ? "border-danger-border bg-danger-subtle" : "border-warning-border bg-warning-subtle"}`} aria-live="polite">
                <div className="flex items-center gap-2">
                  {visibleTerminateAction.status === "verified" ? <CheckCircle2 className="h-4 w-4 text-success" aria-hidden="true" /> : <Power className={`h-4 w-4 ${visibleTerminateAction.status === "failed" ? "text-danger" : "text-warning"}`} aria-hidden="true" />}
                  <span className="text-xs font-semibold text-text">
                    {visibleTerminateAction.status === "verified" ? "Disconnect verified" : visibleTerminateAction.status === "failed" ? "Disconnect failed" : visibleTerminateAction.status === "requested" ? "Reconciling session state" : "Disconnect in progress"}
                  </span>
                </div>
                <p className="mt-1.5 text-xs leading-5 text-text-muted">
                  {visibleTerminateAction.status === "verified" ? "Cowrie confirmed that this exact transport closed." : visibleTerminateAction.status === "failed" ? `No verified closure${visibleTerminateAction.failureCategory ? ` (${visibleTerminateAction.failureCategory.replaceAll("_", " ")})` : ""}.` : visibleTerminateAction.status === "requested" ? "The transport changed state during delivery; awaiting authoritative lifecycle confirmation." : "Request delivered to the Pi; awaiting the session-closed event."}
                </p>
              </div>
            )}
            {visibleTerminateCapability === "loading" ? (
              <RegionState kind="loading" title="Checking response channel" />
            ) : visibleTerminateCapability === "forbidden" ? (
              <RegionState kind="empty" title="Admin access required" description="Only an Admin operator can disconnect a live Cowrie session." />
            ) : visibleTerminateCapability === "unconfigured" ? (
              <RegionState kind="empty" title="Response channel not configured" description="Configure the dashboard-to-Pi response agent before operational controls become available." />
            ) : visibleTerminateCapability === "error" ? (
              <RegionState kind="error" title="Response channel unavailable" description="The control capability could not be verified. No request was sent." />
            ) : !sessionIsLive ? (
              <RegionState kind="empty" title="Session already closed" description="Response actions are disabled for retained audit sessions." />
            ) : visibleTerminateAction && ["requested", "delivered", "verified"].includes(visibleTerminateAction.status) ? null : (
              <div className="rounded-xl border border-danger-border bg-danger-subtle p-3">
                <div className="flex items-start gap-2.5">
                  <Power className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-text">Disconnect this Cowrie session</p>
                    <p className="mt-1 text-xs leading-5 text-text-muted">Closes only transport <span className="font-mono text-text">{selectedSession.sessionId}</span>. It does not block the source IP or run a shell command.</p>
                  </div>
                </div>
                <button type="button" className="ui-button ui-button-danger mt-3 w-full" onClick={() => { setTerminateError(undefined); setTerminateDialogOpen(true); }}>
                  <Power className="h-4 w-4" aria-hidden="true" />
                  Disconnect session
                </button>
              </div>
            )}
                </div>
              ) : (
                /* Tab 1: Route Replay with alert support */
                <>

                  {historyStatus === "error" && !history.length ? (
                    <RegionState
                      kind="error"
                      title="Session history unavailable"
                      description="Route Replay is unavailable, but Command data and Response remain independent."
                    />
                  ) : historyStatus === "loading" && !history.length ? (
                    <RegionState kind="loading" title="Loading session history" />
                  ) : !history.length ? (
                    <RegionState
                      kind="empty"
                      title="No verified directory transitions"
                      description="This session has a known observed path, but Cowrie has not recorded a directory move. Command data and Response remain available from their tabs."
                    />
                  ) : (
                    <>
                      {/* Sleek Compact Hop Deck */}
                      <div className="rounded-xl border border-border bg-surface-subtle p-2.5 shadow-2xs" aria-live="polite">
                        {isAnchoredSelected && (
                          <div
                            role="note"
                            className="mb-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-200"
                            data-testid="anchored-hop-banner"
                          >
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <span>Anchored deep hop: intervening events are unloaded. Replay and adjacent stepping are paused across this gap.</span>
                              {onLoadEarlier && !historyComplete && (
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
                                handlePause();
                                onSelectHistoryEventId(displayedHistory[0]?.id ?? null);
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
                                handlePause();
                                onSelectHistoryEventId(displayedHistory[selectedHistoryIndex - 1]?.id ?? null);
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
                              disabled={isAnchoredSelected || selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
                              onClick={() => {
                                handlePause();
                                onSelectHistoryEventId(displayedHistory[selectedHistoryIndex + 1]?.id ?? null);
                              }}
                            >
                              <ChevronRight className="h-3.5 w-3.5" />
                            </button>

                            <button
                              type="button"
                              className="ui-button h-9 w-9 p-0 shrink-0"
                              title="Jump to latest hop"
                              aria-label="Latest hop"
                              disabled={!isAnchoredSelected && selectedHistoryIndex === displayedHistory.length - 1}
                              onClick={() => {
                                handlePause();
                                onSelectHistoryEventId(displayedHistory.at(-1)?.id ?? null);
                              }}
                            >
                              <FastForward className="h-3 w-3" />
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
                    className="ui-button h-9 min-h-9 px-2 font-mono text-xs shrink-0"
                    title="Toggle playback speed (1x / 2x)"
                  >
                    {playbackSpeed === 1400 ? "1x" : "2x"}
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      if (onTogglePacingMode) {
                        onTogglePacingMode();
                      } else {
                        setInternalPacingMode((current) => (current === "realistic" ? "uniform" : "realistic"));
                      }
                    }}
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
                          if (onToggleShowFailedAttempts) {
                            onToggleShowFailedAttempts(e.target.checked);
                          } else {
                            setInternalShowFailedAttempts(e.target.checked);
                          }
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
                    <span>{timeMetrics.summary.formattedTotalDuration}</span>
                  </span>
                  <span className="truncate">
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
                    max={Math.max(0, displayedHistory.length - 1)}
                    value={selectedHistoryIndex >= 0 ? selectedHistoryIndex : 0}
                    disabled={isAnchoredSelected || displayedHistory.length <= 1}
                    onChange={(e) => {
                      if (isAnchoredSelected) return;
                      handlePause();
                      const targetIndex = Number(e.target.value);
                      const targetEvent = displayedHistory[targetIndex];
                      if (targetEvent) {
                        onSelectHistoryEventId(targetEvent.id);
                      }
                    }}
                    aria-label="Replay timeline scrubber"
                    aria-valuemin={0}
                    aria-valuemax={Math.max(0, displayedHistory.length - 1)}
                    aria-valuenow={selectedHistoryIndex >= 0 ? selectedHistoryIndex : 0}
                    aria-valuetext={
                      isAnchoredSelected
                        ? `Hop ${displayedHistoryMetrics.selectedNumber} of ${displayedHistoryMetrics.totalItems} (Anchored deep target, replay scrubber paused across unloaded gap)`
                        : `Hop ${displayedHistoryMetrics.selectedNumber} of ${displayedHistoryMetrics.totalItems}, elapsed ${timeMetrics.summary.formattedCurrentElapsed}, dwell ${timeMetrics.summary.formattedCurrentDelta}`
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
                      {isInitialSshEntry(selectedHistoryEvent) ? "[SSH Login]" : formatFromPath(selectedHistoryEvent)}
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

            <div className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-text-subtle" aria-live="polite">
              <span>{historyComplete ? "Complete retained history loaded" : `${history.length} of ${historyTotalItems} retained events loaded`}</span>
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
                Load earlier moves ({Math.max(0, historyTotalItems - history.length)} remaining)
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
                              <span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-xs font-semibold text-warning">
                                Failed
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
                        {onLoadEarlier && !historyComplete && (
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
                              {String(explicitHopNumber ?? anchoredHop.hopNumber ?? 1).padStart(2, "0")}
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
        )}
      </>
    )}
  </motion.div>
          </AnimatePresence>
        )}
          </>
        )}
      </div>
      <ConfirmDialog
        open={terminateDialogOpen}
        onOpenChange={setTerminateDialogOpen}
        onConfirm={handleTerminateSession}
        title="Disconnect this live Cowrie session?"
        description={`This immediately closes session ${selectedSession?.sessionId ?? ""} from ${selectedSession?.sourceIp ?? "the selected source"}. The source IP is not blocked and Cowrie remains online.`}
        confirmLabel="Disconnect session"
        confirmVariant="danger"
        isProcessing={terminateProcessing}
        processingLabel="Sending request…"
        errorMessage={terminateError}
      />
      {operationToast && <OperationToast {...operationToast} onDismiss={() => setOperationToast(null)} />}
    </div>
  );
}
