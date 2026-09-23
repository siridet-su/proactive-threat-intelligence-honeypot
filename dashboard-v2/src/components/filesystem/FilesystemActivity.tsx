// @refresh reset
"use client";
import { FilesystemContext, type FilesystemContextType } from "./FilesystemContext";

import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Maximize2,
  Minimize2,
  PanelRightClose,
  PanelRightOpen,
  Pause,
  Play,

  RefreshCw,
  Route,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import type { DateRange } from "react-day-picker";
import { AuditFilterControls, type TimeRangeFilter } from "./AuditFilterControls";
import { AuditSessionSelect } from "./AuditSessionSelect";
import { ResponseActionPanel } from "./ResponseActionPanel";
import { useResponseActionController } from "./ResponseActionController";
import { FilesystemContextPanel } from "./FilesystemContextPanel";
import { AuditFilesystemWorkspace } from "./AuditFilesystemWorkspace";
import { LiveScopeBar } from "./LiveScopeBar";
import { FilesystemPageHeader } from "./FilesystemPageHeader";
import {
  DEFAULT_STALE_THRESHOLD_MS,
  buildAuditSnapshot,
  buildAuditUrlSearch,
  deriveAuditCoverage,

  type AuditUrlParams,
} from "./filesystemUtils";
import { TopologyCanvas } from "./TopologyCanvas";
import { useFilesystemStreaming } from "./useFilesystemStreaming";
import { useSessionCwdHistory } from "./useSessionCwdHistory";
import { useFilesystemUrlState } from "./useFilesystemUrlState";
import { useAuditReplay } from "./useAuditReplay";
import {
  deriveAuthoritativeAuditMetrics,
  formatRetainedSubtitleCoverage,
  useAuditDirectory,
} from "./useAuditDirectory";
import {
  RemoteAuditLookupCoordinator,
  adoptLocalSessionScope,
  createRemoteAuditLookupCallbacks,
  processSnapshotSessionResolution,
  type RemoteAuditLookupIntent,
} from "./sessionHopResolver";
import type { PopStateTransaction } from "./filesystemNavigationCoordinator";
import { handleRovingTabKey } from "./tabSemantics";

interface NavigationApplicationErrorState {
  target: AuditUrlParams;
  targetSearch: string;
  message: string;
}

import { useTimelineDrag } from "./useTimelineDrag";

export type ForensicTab = "replay" | "evidence" | "actions";

const LIVE_WORKSPACE_TABS = ["map", "details"] as const;

export function FilesystemActivity() {
  const [mobileTab, setMobileTab] = useState<"map" | "timeline" | "details">("map");
  const shouldReduceMotion = useReducedMotion();

  // Selected session and path state
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [extraAuditSessions, setExtraAuditSessions] = useState<Map<string, FilesystemClosedSession | FilesystemTopologySession>>(new Map());
  const [navigationApplicationError, setNavigationApplicationError] = useState<NavigationApplicationErrorState | null>(null);

  // Fullscreen & Hybrid Replay Studio State
  const [isAuditFullscreen, setIsAuditFullscreen] = useState(false);
  const [isTimelineCollapsed, setIsTimelineCollapsed] = useState(false);

  const [activeForensicTab, setActiveForensicTab] = useState<ForensicTab>("replay");

  // Cross-cutting refs
  const selectedSessionIdRef = useRef<string | null>(null);
  const selectedLiveCwdRef = useRef<string | null>(null);
  const isMountedRef = useRef(false);
  const auditDialogRef = useRef<HTMLDivElement | null>(null);
  const focusBeforeFullscreenRef = useRef<HTMLElement | null>(null);
  const [remoteAuditLookupManager] = useState(() => {
    return new RemoteAuditLookupCoordinator({
      initialViewMode: "live",
      initialSessionId: null,
      initialTargetHopId: null,
    });
  });
  const lookupRemoteAuditSessionRef = useRef<((intentOrId: RemoteAuditLookupIntent | string, explicitHop?: string | null) => Promise<void> | void) | null>(null);
  const selectSessionRef = useRef<((sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession, targetHopId?: string | null) => void) | null>(null);
  const handleSnapshotAppliedRef = useRef<((data: FilesystemTopologySnapshot) => void) | null>(null);

  // Unmount cleanup: abort any in-flight remote lookup and prevent late
  // navigation-error callbacks from updating detached component state.
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      remoteAuditLookupManager.destroy();
    };
  }, [remoteAuditLookupManager]);

  useEffect(() => {
    selectedSessionIdRef.current = selectedSessionId;
  }, [selectedSessionId]);

  // Persist timeline width preference
  const {
    timelineWidth,
    isDraggingTimeline,
    handleSplitterPointerDown,
    handleSplitterPointerMove,
    handleSplitterPointerUp,
    handleSplitterPointerCancel,
    handleResetTimelineWidth,
    handleSplitterKeyDown,
  } = useTimelineDrag();

  // Streaming & snapshot management hook
  const {
    snapshot,
    regionStatus,
    streamState,
    isHydrated,
    freshnessState,
    refresh,
    handleReconnect,
  } = useFilesystemStreaming({
    onSnapshotApplied: (data) => handleSnapshotAppliedRef.current?.(data),
  });

  const dispatchSelectSession = useCallback((sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession, targetHopId?: string | null) => {
    selectSessionRef.current?.(sessionId, sessionObj, targetHopId);
  }, []);

  const dispatchLookupRemoteAuditSession = useCallback(async (intentOrId: RemoteAuditLookupIntent | string, explicitHop?: string | null) => {
    await lookupRemoteAuditSessionRef.current?.(intentOrId, explicitHop);
  }, []);

  const [timeRange, setTimeRange] = useState<TimeRangeFilter>("all");
  const [customDateRange, setCustomDateRange] = useState<DateRange | undefined>();

  // URL state synchronization and routing hook
  const {
    viewMode,
    viewModeRef,
    switchViewMode,
    hideHomeOnly,
    targetPathFilter,
    selectedHistoryEventId,
    setSelectedHistoryEventId,
    expiredSessionId,
    setExpiredSessionId,
    requestedHopRef,
    requestedSessionIdRef,
    applyInitialUrlState,
    navigationCoordinator,
  } = useFilesystemUrlState({
    timeRange,
    setTimeRange,
    customDateRange,
    setCustomDateRange,
    isHydrated,
    snapshot,
    extraAuditSessions,
    setExtraAuditSessions,
    selectedSessionId,
    selectedSessionIdRef,
    selectSession: dispatchSelectSession,
    lookupRemoteAuditSession: dispatchLookupRemoteAuditSession,
    coordinator: remoteAuditLookupManager,
    setSelectedSessionId,
    onExitFullscreenAndPlaying: () => {
      setIsAuditFullscreen(false);
    },
  });

  const handleNavigationApplicationError = useCallback(
    (_error: unknown, transaction: PopStateTransaction) => {
      if (!isMountedRef.current) return;
      try {
        const target = { ...transaction.target };
        setNavigationApplicationError({
          target,
          targetSearch: buildAuditUrlSearch(target),
          message: "We couldn't complete this navigation. Retry or choose another destination.",
        });
      } catch {
        // Error reporting is deliberately bounded and cannot break navigation.
      }
    },
    [],
  );

  const handleNavigationTransactionStarted = useCallback(() => {
    if (isMountedRef.current) {
      setNavigationApplicationError(null);
    }
  }, []);

  const retryNavigationApplication = useCallback(() => {
    const failure = navigationApplicationError;
    if (!failure) return;
    navigationCoordinator.recoverFailedTransaction();
    setNavigationApplicationError(null);
    navigationCoordinator.handlePopState(failure.targetSearch);
  }, [navigationApplicationError, navigationCoordinator]);

  const dismissNavigationApplicationError = useCallback(() => {
    navigationCoordinator.recoverFailedTransaction();
    setNavigationApplicationError(null);
  }, [navigationCoordinator]);

  const handleSelectHistoryEventId = useCallback(
    (eventId: string | null, source: "user" | "playback" | "sync" = "user") => {
      if (source === "user") {
        navigationCoordinator.userSelectHop(eventId);
      } else if (source === "playback") {
        navigationCoordinator.playbackSelectHop(eventId);
      } else {
        requestedHopRef.current = eventId;
        setSelectedHistoryEventId(eventId);
      }
    },
    [navigationCoordinator, requestedHopRef, setSelectedHistoryEventId],
  );

  useEffect(() => {
    remoteAuditLookupManager.notifyViewModeChanged(viewMode);
  }, [remoteAuditLookupManager, viewMode]);

  // Session CWD history keyset pagination hook
  const {
    history,
    anchoredHop,
    historyCursor,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    historyStatus,
    hopResolutionStatus,
    requestedHop,
    clearRequestedHop,
    resetRequestedHopState,
    selectLatestHop,
    loadHistory,
    resetHistory,
  } = useSessionCwdHistory({
    requestedHopRef,
    onSelectHistoryEventId: handleSelectHistoryEventId,
    viewMode,
  });

  // Audit replay scrubber, timer, and active hop route hook
  const {
    isPlaying,
    setIsPlaying,
    playbackSpeed,
    displayedHistory,
    selectedHistoryIndex,
    displayedHistoryMetrics,
    activeHop,
    displayedTransitions,
    currentTransition,
    onPrevHop: handlePrevHop,
    onNextHop: handleNextHop,
    onTogglePlay: handleTogglePlay,
    presentation: replayPresentation,
  } = useAuditReplay({
    viewMode,
    history,
    anchoredHop,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    selectedHistoryEventId,
    onSelectHistoryEventId: handleSelectHistoryEventId,
  });

  const handleSnapshotApplied = useCallback((data: FilesystemTopologySnapshot) => {
    const resolution = processSnapshotSessionResolution({
      snapshot: data,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: viewModeRef.current,
      lookupRemoteAuditSession: (intent) => lookupRemoteAuditSessionRef.current?.(intent),
      setExpiredSessionId,
      setSelectedSessionId,
      coordinator: remoteAuditLookupManager,
    });

    const nextSessionId = resolution.sessionId;
    const selectedLiveSession = data.sessions.find((session) => session.sessionId === nextSessionId) ?? null;

    const liveCwdChanged =
      Boolean(selectedLiveSession?.cwdState.path) &&
      selectedLiveSession?.cwdState.path !== selectedLiveCwdRef.current;
    selectedLiveCwdRef.current = selectedLiveSession?.cwdState.path ?? null;

    setSelectedPath((current) => {
      // Live snapshots are not authoritative for the retained audit graph. In
      // audit mode, keep the operator's inspected path across stream refreshes;
      // session and replay navigation update it through their own owners.
      if (viewModeRef.current === "audit") return current;
      // If the active session actually changed its working directory, follow the new CWD.
      if (liveCwdChanged && selectedLiveSession?.cwdState.path && data.nodes.some((node) => node.path === selectedLiveSession.cwdState.path)) {
        return selectedLiveSession.cwdState.path;
      }
      // Otherwise, preserve the user's manual inspection target if it still exists in the graph.
      const valid = current && data.nodes.some((node) => node.path === current);
      if (valid) return current;
      return selectedLiveSession?.cwdState.path ?? data.sessions[0]?.cwdState.path ?? data.nodes[0]?.path ?? null;
    });
  }, [extraAuditSessions, viewModeRef, setExpiredSessionId, requestedSessionIdRef, requestedHopRef, remoteAuditLookupManager]);

  useEffect(() => {
    handleSnapshotAppliedRef.current = handleSnapshotApplied;
  }, [handleSnapshotApplied]);

  // Authoritative closed session audit directory hook
  const {
    authoritativeClosedSessions,
    auditDirectoryTotalCount,
    directoryHasMore,
    directoryIsLoading,
    directoryIsComplete,
    loadMoreDirectory,
    searchItems: auditSearchItems,
    searchHasMore: auditSearchHasMore,
    searchIsLoading: auditSearchIsLoading,
    searchIsComplete: auditSearchIsComplete,
    searchSessions: searchAuditSessions,
    loadMoreSearch: loadMoreAuditSearch,
    clearSearch: clearAuditSearch,
    summary: auditSummary,
    summaryScopeKey: auditSummaryScopeKey,
    currentScopeKey: auditCurrentScopeKey,
    summaryStatus: auditSummaryStatus,
    status: auditStatus,
    errorMessage: auditErrorMessage,
    retryInitialDirectory,
    recordLookedUpSession,
  } = useAuditDirectory({
    viewMode,
    snapshotRecentClosedSessions: snapshot?.recentClosedSessions ?? [],
    extraAuditSessions,
    hideHomeOnly,
    targetPathFilter,
    timeRange,
    customDateRange,
  });

  const {
    allSessions,
    sessionById,
    distinctPaths,
    filteredActiveSessions,
    filteredClosedSessions,
    homeOnlyCount,
    totalSessionsCount,
    filteredSessionsCount,
    isSelectedFilteredOut,
    retainedLoadedCount,
    retainedMatchingCount,
    retainedTotalCount,
    retainedCountStatus,
  } = useMemo(() => {
    return deriveAuthoritativeAuditMetrics({
      viewMode,
      activeSessions: snapshot?.sessions ?? [],
      authoritativeClosedSessions,
      snapshotRecentClosedSessions: snapshot?.recentClosedSessions ?? [],
      summary: auditSummary,
      summaryScopeKey: auditSummaryScopeKey,
      currentScopeKey: auditCurrentScopeKey,
      summaryStatus: auditSummaryStatus,
      auditDirectoryTotalCount,
      hideHomeOnly,
      targetPathFilter,
      selectedSessionId,
      isDirectoryComplete: directoryIsComplete,
      timeRange,
      customDateRange,
    });
  }, [
    viewMode,
    snapshot?.sessions,
    authoritativeClosedSessions,
    snapshot?.recentClosedSessions,
    auditSummary,
    auditSummaryScopeKey,
    auditCurrentScopeKey,
    auditSummaryStatus,
    auditDirectoryTotalCount,
    hideHomeOnly,
    targetPathFilter,
    selectedSessionId,
    directoryIsComplete,
    timeRange,
    customDateRange,
  ]);

  const selectedSession = useMemo(
    () => sessionById.get(selectedSessionId ?? "") ?? null,
    [selectedSessionId, sessionById],
  );

  // Explicit page-level response lifecycle owner. CwdRouteHistory only renders
  // the supplied response view model and never starts capability requests or polling.
  const responseAction = useResponseActionController({
    selectedSession,
    sessionIsLive: Boolean(selectedSessionId && snapshot?.sessions.some((session) => session.sessionId === selectedSessionId)),
    enabled: viewMode === "audit" && activeForensicTab === "actions" && Boolean(selectedSession),
  });
  const responsePanel = (
    <ResponseActionPanel
      selectedSession={selectedSession}
      sessionIsLive={Boolean(selectedSessionId && snapshot?.sessions.some((session) => session.sessionId === selectedSessionId))}
      visibleTerminateAction={responseAction.visibleTerminateAction}
      visibleTerminateCapability={responseAction.visibleTerminateCapability}
      terminateDialogOpen={responseAction.terminateDialogOpen}
      onTerminateDialogOpenChange={responseAction.setTerminateDialogOpen}
      terminateProcessing={responseAction.terminateProcessing}
      terminateError={responseAction.terminateError}
      onTerminateErrorChange={responseAction.setTerminateError}
      operationToast={responseAction.operationToast}
      onOperationToastChange={responseAction.setOperationToast}
      onTerminateSession={responseAction.handleTerminateSession}
    />
  );

  const selectedClosedSession = useMemo(() => {
    const fromAuthoritative = authoritativeClosedSessions.find((s) => s.sessionId === selectedSessionId);
    if (fromAuthoritative) return fromAuthoritative;
    const fromSnapshot = snapshot?.recentClosedSessions.find((s) => s.sessionId === selectedSessionId);
    if (fromSnapshot) return fromSnapshot;
    const fromExtra = extraAuditSessions.get(selectedSessionId ?? "");
    if (fromExtra && "lifecycle" in fromExtra && Boolean(fromExtra.lifecycle)) {
      return fromExtra as FilesystemClosedSession;
    }
    return null;
  }, [selectedSessionId, authoritativeClosedSessions, snapshot, extraAuditSessions]);

  const selectedNode = useMemo(
    () => snapshot?.nodes.find((n) => n.path === selectedPath) ?? null,
    [selectedPath, snapshot],
  );

  const hasActiveFilters = hideHomeOnly || targetPathFilter !== null || timeRange !== "all";

  const handleResetAuditFilters = useCallback(() => {
    navigationCoordinator.userResetFilters();
    setTimeRange("all");
    setCustomDateRange(undefined);
  }, [navigationCoordinator]);

  const auditCanvasTitle = useMemo(() => {
    if (!selectedSession) return "No Session Selected";
    if (isSelectedFilteredOut) {
      return `Attack Trajectory: ${selectedSession.sourceIp} (Pinned Outside Filter)`;
    }
    return `Attack Trajectory: ${selectedSession.sourceIp}`;
  }, [selectedSession, isSelectedFilteredOut]);

  const auditCanvasSubtitle = useMemo(() => {
    if (!selectedSession) return "Choose a session from the dropdown to replay its filesystem trajectory.";

    const coverageModel = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: history.length,
      historyTotalItems,
      historyComplete,
      historyStatus,
      auditSummaryEventCount: selectedSession.auditSummary?.eventCount,
    });
    const coverageWording = coverageModel.wording;

    return formatRetainedSubtitleCoverage({
      retainedMatchingCount,
      retainedLoadedCount,
      retainedCountStatus,
      isSelectedFilteredOut,
      hasActiveFilters,
      coverageWording,
    });
  }, [
    selectedSession,
    retainedMatchingCount,
    retainedLoadedCount,
    retainedCountStatus,
    isSelectedFilteredOut,
    hasActiveFilters,
    history.length,
    historyTotalItems,
    historyComplete,
    historyStatus,
  ]);

  // Reload CWD route when a new source event arrives for the selected session
  useEffect(() => {
    if (!selectedSessionId) return;
    const request = window.setTimeout(() => {
      void loadHistory(selectedSessionId, null);
    }, 0);
    return () => {
      window.clearTimeout(request);
    };
  }, [loadHistory, selectedSession?.cwdState.sourceEventId, selectedSessionId]);

  const selectSession = useCallback(
    (
      sessionId: string,
      sessionObj?: FilesystemTopologySession | FilesystemClosedSession,
      targetHopId?: string | null,
    ) => {
      const currentMode = viewModeRef.current;
      const effectiveHop = adoptLocalSessionScope({
        coordinator: remoteAuditLookupManager,
        viewMode: currentMode,
        sessionId,
        targetHopId,
      });

      const isDifferentSession = sessionId !== selectedSessionIdRef.current;
      const session = sessionObj ?? sessionById.get(sessionId);
      setExpiredSessionId(null);
      if (isDifferentSession) {
        resetHistory();
        if (effectiveHop !== null) {
          requestedHopRef.current = effectiveHop;
          setSelectedHistoryEventId(effectiveHop);
        } else {
          requestedHopRef.current = null;
          setSelectedHistoryEventId(null);
        }
      } else if (effectiveHop !== null) {
        requestedHopRef.current = effectiveHop;
        setSelectedHistoryEventId(effectiveHop);
      } else if (targetHopId === null) {
        requestedHopRef.current = null;
        setSelectedHistoryEventId(null);
      }
      setIsPlaying(false);
      selectedSessionIdRef.current = sessionId;
      setSelectedSessionId(sessionId);
      if (session?.cwdState.path) {
        selectedLiveCwdRef.current = session.cwdState.path;
        setSelectedPath(snapshot?.nodes.some((n) => n.path === session.cwdState.path) ? session.cwdState.path : null);
      }
      void loadHistory(sessionId, null);
    },
    [remoteAuditLookupManager, sessionById, snapshot?.nodes, loadHistory, resetHistory, requestedHopRef, setSelectedHistoryEventId, setIsPlaying, setExpiredSessionId, setSelectedSessionId, viewModeRef],
  );

  useEffect(() => {
    selectSessionRef.current = selectSession;
  }, [selectSession]);

  useEffect(() => {
    remoteAuditLookupManager.setCallbacks(
      createRemoteAuditLookupCallbacks({
        recordLookedUpSession,
        setExtraAuditSessions,
        setExpiredSessionId,
        selectSession,
        setSelectedSessionId,
        clearSelectedSessionRef: () => {
          selectedSessionIdRef.current = null;
        },
      }),
    );
  }, [
    recordLookedUpSession,
    selectSession,
    setExpiredSessionId,
    setSelectedSessionId,
    remoteAuditLookupManager,
  ]);

  const lookupRemoteAuditSession = useCallback(
    async (intentOrId: RemoteAuditLookupIntent | string, explicitHop?: string | null) => {
      const intent: RemoteAuditLookupIntent =
        typeof intentOrId === "string"
          ? { sessionId: intentOrId, targetHopId: explicitHop }
          : intentOrId;
      if (!intent.sessionId) return;
      await remoteAuditLookupManager.lookup(intent);
    },
    [remoteAuditLookupManager],
  );

  useEffect(() => {
    lookupRemoteAuditSessionRef.current = lookupRemoteAuditSession;
  }, [lookupRemoteAuditSession]);

  useEffect(() => {
    navigationCoordinator.bindDomainAdapter({
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,
      selectSession,
      recordLookedUpSession,
      onNavigationApplicationError: handleNavigationApplicationError,
      onNavigationTransactionStarted: handleNavigationTransactionStarted,
      resetHistory,
      resetRequestedHopState,
      onExitFullscreenAndPlaying: () => {
        setIsPlaying(false);
        setIsAuditFullscreen(false);
      },
      coordinator: remoteAuditLookupManager,
      lookupRemoteAuditSession: (intent) => lookupRemoteAuditSessionRef.current?.(intent),
    });
  }, [
    allSessions,
    sessionById,
    navigationCoordinator,
    remoteAuditLookupManager,
    recordLookedUpSession,
    handleNavigationApplicationError,
    handleNavigationTransactionStarted,
    resetHistory,
    resetRequestedHopState,
    selectSession,
    setIsPlaying,
  ]);

  useEffect(() => {
    applyInitialUrlState();
  }, [applyInitialUrlState]);

  const handleUserSelectSession = useCallback(
    (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => {
      navigationCoordinator.userSelectSession(sessionId, sessionObj);
    },
    [navigationCoordinator],
  );

  const handleTimeFilterChange = useCallback((newTimeRange: TimeRangeFilter, newDateRange: DateRange | undefined) => {
    navigationCoordinator.commit({
      timeRange: newTimeRange,
      timeFrom: newDateRange?.from?.getTime() ?? null,
      timeTo: newDateRange?.to?.getTime() ?? null,
    }, "push");
  }, [navigationCoordinator]);

  const handleToggleHideHomeOnly = useCallback(() => {
    navigationCoordinator.userToggleHideHome();
  }, [navigationCoordinator]);

  const handleSelectTargetPath = useCallback(
    (path: string | null) => {
      navigationCoordinator.userSelectTargetPath(path);
    },
    [navigationCoordinator],
  );

  const handleClearSelection = useCallback(() => {
    navigationCoordinator.userClearSelection();
  }, [navigationCoordinator]);

  // Decoupled directory selection: inspects directory metadata without destroying the currently audited session
  const selectPath = (path: string | null) => {
    setSelectedPath(path);
  };


  const auditSnapshot = useMemo(() => {
    if (viewMode !== "audit") return null;
    return buildAuditSnapshot(snapshot, selectedSession, history);
  }, [viewMode, snapshot, selectedSession, history]);

  const enterAuditFullscreen = useCallback(() => {
    focusBeforeFullscreenRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setIsAuditFullscreen(true);
  }, []);

  // Global audit keyboard shortcuts (Space: play/pause, Left/Right: step, Esc: exit fullscreen)
  useEffect(() => {
    if (viewMode !== "audit") return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && isAuditFullscreen) {
        event.preventDefault();
        setIsAuditFullscreen(false);
        return;
      }

      const target = event.target instanceof HTMLElement ? event.target : null;
      if (
        target?.closest(
          'a, button, input, select, textarea, summary, [role="combobox"], [role="listbox"], [role="region"], [contenteditable="true"]',
        )
      ) return;

      if (event.key === " " || event.code === "Space") {
        event.preventDefault();
        handleTogglePlay();
      } else if (event.key === "ArrowLeft") {
        event.preventDefault();
        handlePrevHop();
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        handleNextHop();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [viewMode, isAuditFullscreen, handleTogglePlay, handlePrevHop, handleNextHop]);

  // Keep keyboard focus inside the modal workspace and restore it to the invoking control.
  useEffect(() => {
    if (!isAuditFullscreen) return;
    const dialog = auditDialogRef.current;
    if (!dialog) return;
    const focusableSelector = [
      'button:not([disabled])',
      'a[href]',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
    ].join(",");
    const focusInitial = window.requestAnimationFrame(() => {
      (dialog.querySelector<HTMLElement>(focusableSelector) ?? dialog).focus();
    });
    const trapFocus = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const focusable = [...dialog.querySelectorAll<HTMLElement>(focusableSelector)].filter(
        (element) =>
          !element.closest("[inert]") &&
          !element.closest('[aria-hidden="true"]') &&
          element.getClientRects().length > 0,
      );
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", trapFocus);
    return () => {
      const previousFocus = focusBeforeFullscreenRef.current;
      window.cancelAnimationFrame(focusInitial);
      document.removeEventListener("keydown", trapFocus);
      focusBeforeFullscreenRef.current = null;
      window.requestAnimationFrame(() => {
        if (previousFocus?.isConnected) {
          previousFocus.focus();
          return;
        }
        document.querySelector<HTMLElement>('[data-audit-fullscreen-trigger="true"]')?.focus();
      });
    };
  }, [isAuditFullscreen]);

  // Lock body scroll when audit fullscreen is active
  useEffect(() => {
    if (!isAuditFullscreen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [isAuditFullscreen]);


  const contextValue = {
    viewMode,
    mobileTab,
    setMobileTab,
    isAuditFullscreen,
    setIsAuditFullscreen,
    directoryHasMore,
    directoryIsLoading,
    directoryIsComplete,
    loadMoreDirectory,
    auditSearchItems,
    auditSearchHasMore,
    auditSearchIsLoading,
    auditSearchIsComplete,
    searchAuditSessions,
    loadMoreAuditSearch,
    clearAuditSearch,
    auditStatus,
    auditErrorMessage,
    retryInitialDirectory,
    handleToggleHideHomeOnly,
    handleSelectTargetPath,
    distinctPaths,
    homeOnlyCount,
    expiredSessionId,
    allSessions,
    setExpiredSessionId,
    handleUserSelectSession,
    switchViewMode,
    hasActiveFilters,
    isSelectedFilteredOut,
    filteredSessionsCount,
    totalSessionsCount,
    targetPathFilter,
    hideHomeOnly,
    selectedSession,
    filteredActiveSessions,
    filteredClosedSessions,
    handleResetAuditFilters,
    handleClearSelection,
    retainedLoadedCount,
    retainedMatchingCount,
    retainedTotalCount,
    retainedCountStatus,
    auditSnapshot,
    snapshot,
    regionStatus,
    streamState,
    freshnessState,
    selectedSessionId,
    selectedPath,
    activeHop,
    displayedTransitions,
    currentTransition,
    playbackSpeed,
    auditCanvasTitle,
    auditCanvasSubtitle,
    selectPath,
    refresh,
    handleReconnect,
    isDraggingTimeline,
    isTimelineCollapsed,
    timelineWidth,
    handleSplitterPointerDown,
    handleSplitterPointerMove,
    handleSplitterPointerUp,
    handleSplitterPointerCancel,
    handleResetTimelineWidth,
    handleSplitterKeyDown,
    history,
    anchoredHop,
    historyStatus,
    historyCursor,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    replayPresentation,
    activeForensicTab,
    setActiveForensicTab,
    responsePanel,
    hopResolutionStatus,
    requestedHop,
    clearRequestedHop,
    selectLatestHop,
    handleSelectHistoryEventId,
    loadHistory,
  };

  return (
    <FilesystemContext.Provider value={contextValue as FilesystemContextType}>
    <div className="filesystem-activity-scope min-w-0 space-y-5 overflow-x-hidden pb-10 sm:pb-14">

      {navigationApplicationError ? (
        <div
          role="alert"
          aria-live="assertive"
          className="flex flex-wrap items-center gap-3 rounded-lg border border-danger-border bg-danger-subtle px-4 py-3 text-sm text-danger"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
          <p className="min-w-0 flex-1">{navigationApplicationError.message}</p>
          <button type="button" className="ui-button" onClick={retryNavigationApplication}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Retry
          </button>
          <button type="button" className="ui-button" onClick={dismissNavigationApplicationError}>
            Dismiss
          </button>
        </div>
      ) : null}
      {/* Header Section: Global view controls and real-time telemetry status */}
      <FilesystemPageHeader
        viewMode={viewMode}
        switchViewMode={switchViewMode}
        snapshot={snapshot}
        streamState={streamState}
        freshnessState={freshnessState}
        handleReconnect={handleReconnect}
        regionStatus={regionStatus}
        refresh={refresh}
      />

      {/* Mode 1: Live Global Topology Mode */}
      {viewMode === "live" ? (
        <div
          id="filesystem-live-panel"
          role="tabpanel"
          aria-labelledby="filesystem-live-tab"
          className="flex flex-col lg:grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-stretch min-h-[calc(100dvh-12rem)] lg:flex-1"
        >
          {/* Mobile Tabs */}
          <div
            className="flex lg:hidden gap-2 border-b border-border pb-2"
            role="tablist"
            aria-label="Live workspace views"
          >
            <button
              id="live-map-tab"
              type="button"
              role="tab"
              aria-selected={mobileTab === "map"}
              aria-controls="live-map-panel"
              tabIndex={mobileTab === "map" ? 0 : -1}
              onClick={() => setMobileTab('map')}
              onKeyDown={(event) => handleRovingTabKey({
                event,
                tabs: LIVE_WORKSPACE_TABS,
                currentTab: "map",
                onSelect: setMobileTab,
                tabId: (tab) => `live-${tab}-tab`,
              })}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg ${mobileTab === 'map' ? 'bg-surface border-b-2 border-primary text-primary' : 'text-text-subtle'}`}
            >
              Map
            </button>
            <button
              id="live-details-tab"
              type="button"
              role="tab"
              aria-selected={mobileTab === "details"}
              aria-controls="live-details-panel"
              tabIndex={mobileTab === "details" ? 0 : -1}
              onClick={() => setMobileTab('details')}
              onKeyDown={(event) => handleRovingTabKey({
                event,
                tabs: LIVE_WORKSPACE_TABS,
                currentTab: "details",
                onSelect: setMobileTab,
                tabId: (tab) => `live-${tab}-tab`,
              })}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg ${mobileTab === 'details' ? 'bg-surface border-b-2 border-primary text-primary' : 'text-text-subtle'}`}
            >
              Details
            </button>
          </div>

          <div
            id="live-map-panel"
            role="tabpanel"
            aria-labelledby="live-map-tab"
            className={`min-w-0 flex-1 flex-col gap-4 ${mobileTab === 'map' ? 'flex' : 'hidden'} lg:flex`}
          >
            <LiveScopeBar snapshot={snapshot} />
            <TopologyCanvas
              snapshot={snapshot}
              regionStatus={regionStatus}
              streamState={streamState}
              freshnessState={freshnessState}
              selectedSessionId={selectedSessionId}
              selectedPath={selectedPath}
              onSelectSession={selectSession}
              onSelectPath={selectPath}
              onRefresh={refresh}
              onReconnect={handleReconnect}
              staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
              presentationContext={{ mode: "live" }}
              className="flex-1"
            />
          </div>

          <div
            id="live-details-panel"
            role="tabpanel"
            aria-labelledby="live-details-tab"
            className={`${mobileTab === 'details' ? 'block' : 'hidden'} lg:block`}
          >
            <FilesystemContextPanel
              selectedSession={selectedSession}
              selectedClosedSession={selectedClosedSession}
              selectedNode={selectedNode}
              sessions={snapshot?.sessions ?? []}
              recentClosedSessions={snapshot?.recentClosedSessions ?? []}
              selectedSessionId={selectedSessionId}
              onSelectSession={selectSession}
              onSelectPath={selectPath}
              onOpenAudit={(sessionId) => switchViewMode("audit", sessionId)}
            />
          </div>
        </div>
      ) : (
        <div
          id="filesystem-audit-panel"
          role="tabpanel"
          aria-labelledby="filesystem-audit-tab"
        >
          <div
            ref={isAuditFullscreen ? auditDialogRef : undefined}
            role={isAuditFullscreen ? "dialog" : undefined}
            aria-modal={isAuditFullscreen ? true : undefined}
            aria-label={isAuditFullscreen ? "Audit Replay Studio Fullscreen" : undefined}
            tabIndex={isAuditFullscreen ? -1 : undefined}
            className={
              isAuditFullscreen
                ? "fixed inset-0 z-50 flex flex-col bg-surface-subtle p-2.5 sm:p-3.5 gap-2.5 overflow-hidden text-text"
                : "space-y-4"
            }
          >
          {isAuditFullscreen ? (
          /* Mode 2 Fullscreen: Dedicated Forensic Replay Cockpit (Hybrid 70/30 with Collapse) */
          <header className="relative z-30 grid shrink-0 grid-cols-1 items-start gap-2 rounded-xl border border-border bg-surface px-3 py-2 shadow-xs xl:grid-cols-[minmax(0,1fr)_auto]">
            <div
              className="flex min-w-0 flex-wrap items-center gap-1.5"
              role="group"
              aria-label="Studio identity and session scope"
            >
              <div className="flex items-center gap-2 shrink-0">
                <Route className="h-4 w-4 text-primary" aria-hidden="true" />
                <span className="text-sm font-semibold text-text">Audit Replay Studio</span>
              </div>
              <div className="h-4 w-px bg-border hidden sm:block shrink-0" aria-hidden="true" />
              <span className="text-xs text-text-subtle font-medium hidden md:inline shrink-0">Audited Session:</span>
              <div className="flex items-center gap-2 flex-wrap min-w-0" role="group" aria-label="Session and filter selectors">
                <AuditSessionSelect
                  sessions={filteredActiveSessions}
                  recentClosedSessions={filteredClosedSessions}
                  selectedSessionId={selectedSessionId}
                  onSelectSession={handleUserSelectSession}
                  totalCount={totalSessionsCount}
                  hasActiveFilters={hasActiveFilters}
                  onResetFilters={handleResetAuditFilters}
                  allSessionsList={allSessions}
                  directoryHasMore={directoryHasMore}
                  directoryIsLoading={directoryIsLoading}
                  directoryIsComplete={directoryIsComplete}
                  onLoadMoreDirectory={loadMoreDirectory}
                  searchResults={auditSearchItems}
                  searchHasMore={auditSearchHasMore}
                  searchIsLoading={auditSearchIsLoading}
                  searchIsComplete={auditSearchIsComplete}
                  onSearch={(q) => void searchAuditSessions(q)}
                  onLoadMoreSearch={loadMoreAuditSearch}
                  onClearSearch={clearAuditSearch}
                  hideHomeOnly={hideHomeOnly}
                  targetPathFilter={targetPathFilter}
                  timeRange={timeRange}
                  retainedMatchingCount={retainedMatchingCount}
                  retainedLoadedCount={retainedLoadedCount}
                  retainedCountStatus={retainedCountStatus}
                  status={auditStatus}
                  errorMessage={auditErrorMessage}
                  onRetry={retryInitialDirectory}
                />
                <AuditFilterControls
                  hideHomeOnly={hideHomeOnly}
                  onToggleHideHomeOnly={handleToggleHideHomeOnly}
                  targetPath={targetPathFilter}
                  onSelectTargetPath={handleSelectTargetPath}
                  timeRange={timeRange}
                  onSelectTimeRange={setTimeRange}
                  customDateRange={customDateRange}
                  onSelectCustomDateRange={setCustomDateRange}
                  onTimeFilterChange={handleTimeFilterChange}
                  distinctPaths={distinctPaths}
                  homeOnlyCount={homeOnlyCount}
                  filteredCount={filteredSessionsCount}
                  totalCount={totalSessionsCount}
                  onResetFilters={handleResetAuditFilters}
                  selectedCanvasPath={selectedPath}
                  retainedMatchingCount={retainedMatchingCount}
                  retainedLoadedCount={retainedLoadedCount}
                  retainedTotalCount={retainedTotalCount}
                  retainedCountStatus={retainedCountStatus}
                />
              </div>
              {selectedSession && (
                <span className="font-mono text-xs text-text-subtle hidden xl:inline shrink-0">
                  IP: <strong className="text-text">{selectedSession.sourceIp}</strong>
                </span>
              )}
            </div>

            {/* Stable right-side control cluster */}
            <div
              className="flex min-h-10 flex-wrap items-center justify-start sm:justify-end gap-2 justify-self-start sm:justify-self-end xl:flex-nowrap"
              role="toolbar"
              aria-label="Studio replay and workspace actions"
            >
              {displayedHistory.length > 0 && (
                <div
                  className="relative h-10 w-72 shrink-0 overflow-hidden"
                  role="group"
                  aria-label="Quick replay scrubber"
                >
                  <AnimatePresence initial={false} mode="wait">
                    {isTimelineCollapsed ? (
                      <motion.div
                        key="quick-replay"
                        initial={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, x: 32, scale: 0.96 }}
                        animate={{ opacity: 1, x: 0, scale: 1 }}
                        exit={shouldReduceMotion ? { opacity: 0 } : { opacity: 0, x: 32, scale: 0.96 }}
                        transition={{ duration: shouldReduceMotion ? 0 : 0.16, ease: "easeOut" }}
                        className="absolute inset-0 flex items-center justify-end"
                      >
                        <div className="flex h-10 items-center gap-1 rounded-lg border border-border bg-surface-subtle p-0.5">
                          <button
                            type="button"
                            onClick={handlePrevHop}
                            disabled={selectedHistoryIndex <= 0}
                            className="ui-button h-9 min-h-9 w-9 p-0"
                            title="Previous hop (←)"
                            aria-label="Previous hop"
                            data-keyboard-tooltip
                          >
                            <ChevronLeft className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={handleTogglePlay}
                            className={`ui-button h-9 min-h-9 px-2.5 text-xs flex items-center gap-1 ${
                              isPlaying ? "border-primary bg-primary text-surface" : ""
                            }`}
                            title={isPlaying ? "Pause auto-playback (Space)" : "Play route trajectory automatically (Space)"}
                            aria-label={isPlaying ? "Pause auto-playback" : "Play route trajectory automatically"}
                          >
                            {isPlaying ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
                            <span>{isPlaying ? "Pause" : "Play"}</span>
                          </button>
                          <button
                            type="button"
                            onClick={handleNextHop}
                            disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
                            className="ui-button h-9 min-h-9 w-9 p-0"
                            title="Next hop (→)"
                            aria-label="Next hop"
                            data-keyboard-tooltip
                          >
                            <ChevronRight className="h-3.5 w-3.5" />
                          </button>
                          <span className="border-l border-border/60 px-1.5 font-mono text-xs text-text-muted">
                            Hop <strong className="text-primary">{displayedHistoryMetrics.selectedNumber}</strong> of {displayedHistoryMetrics.totalItems}
                          </span>
                        </div>
                      </motion.div>
                    ) : (
                      <motion.div
                        key="keyboard-hints"
                        initial={shouldReduceMotion ? { opacity: 1 } : { opacity: 0, x: 32, scale: 0.96 }}
                        animate={{ opacity: 1, x: 0, scale: 1 }}
                        exit={shouldReduceMotion ? { opacity: 0 } : { opacity: 0, x: 32, scale: 0.96 }}
                        transition={{ duration: shouldReduceMotion ? 0 : 0.16, ease: "easeOut" }}
                        className="absolute inset-0 flex h-10 items-center justify-end gap-1.5 font-mono text-xs text-text-subtle"
                      >
                        <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 shadow-2xs">Space</kbd> Play
                        <span className="text-border">·</span>
                        <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 shadow-2xs">←</kbd>
                        <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 shadow-2xs">→</kbd> Step
                        <span className="text-border">·</span>
                        <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 shadow-2xs">Esc</kbd> Exit
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}

              <div className="flex items-center gap-1.5 shrink-0" role="group" aria-label="Workspace views">
                {/* Toggle Timeline Collapse (70/30 vs 100%) */}
                <button
                  type="button"
                  onClick={() => setIsTimelineCollapsed((c) => !c)}
                  className="ui-button h-9 px-2.5 text-xs flex items-center gap-1.5"
                  title={isTimelineCollapsed ? "Show timeline sidebar" : "Collapse timeline sidebar"}
                  aria-pressed={isTimelineCollapsed}
                >
                  {isTimelineCollapsed ? <PanelRightOpen className="h-3.5 w-3.5" /> : <PanelRightClose className="h-3.5 w-3.5" />}
                  <span className="hidden sm:inline">{isTimelineCollapsed ? "Show Timeline" : "Hide Timeline"}</span>
                </button>

                {/* Exit Fullscreen Button */}
                <button
                  type="button"
                  onClick={() => setIsAuditFullscreen(false)}
                  className="ui-button h-9 px-2.5 text-xs flex items-center gap-1.5 bg-surface-subtle hover:bg-surface-hover"
                  title="Exit Fullscreen Studio (Esc)"
                  aria-label="Exit Fullscreen Studio"
                >
                  <Minimize2 className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Exit Fullscreen</span>
                </button>
              </div>
            </div>
          </header>
          ) : (
          /* Mode 2: Session Forensics & Replay Mode (Side-by-Side In-Page View) */
          <div
            className="relative z-30 flex flex-col xl:flex-row xl:items-center justify-between gap-2 rounded-xl border border-border bg-surface px-2.5 py-1.5 shadow-xs"
            role="toolbar"
            aria-label="Audit session and replay toolbar"
          >
            {/* Left side: Selection & Filters */}
            <div className="flex items-center justify-start gap-2 flex-1 min-w-0">
              <div
                className="flex flex-wrap items-center gap-1.5 min-w-0"
                role="group"
                aria-label="Audited session and filter controls"
              >
                <AuditSessionSelect
                  sessions={filteredActiveSessions}
                  recentClosedSessions={filteredClosedSessions}
                  selectedSessionId={selectedSessionId}
                  onSelectSession={handleUserSelectSession}
                  totalCount={totalSessionsCount}
                  hasActiveFilters={hasActiveFilters}
                  onResetFilters={handleResetAuditFilters}
                  allSessionsList={allSessions}
                  directoryHasMore={directoryHasMore}
                  directoryIsLoading={directoryIsLoading}
                  directoryIsComplete={directoryIsComplete}
                  onLoadMoreDirectory={loadMoreDirectory}
                  searchResults={auditSearchItems}
                  searchHasMore={auditSearchHasMore}
                  searchIsLoading={auditSearchIsLoading}
                  searchIsComplete={auditSearchIsComplete}
                  onSearch={(q) => void searchAuditSessions(q)}
                  onLoadMoreSearch={loadMoreAuditSearch}
                  onClearSearch={clearAuditSearch}
                  hideHomeOnly={hideHomeOnly}
                  targetPathFilter={targetPathFilter}
                  timeRange={timeRange}
                  retainedMatchingCount={retainedMatchingCount}
                  retainedLoadedCount={retainedLoadedCount}
                  retainedCountStatus={retainedCountStatus}
                  status={auditStatus}
                  errorMessage={auditErrorMessage}
                  onRetry={retryInitialDirectory}
                />
                <AuditFilterControls
                  hideHomeOnly={hideHomeOnly}
                  onToggleHideHomeOnly={handleToggleHideHomeOnly}
                  targetPath={targetPathFilter}
                  onSelectTargetPath={handleSelectTargetPath}
                  timeRange={timeRange}
                  onSelectTimeRange={setTimeRange}
                  customDateRange={customDateRange}
                  onSelectCustomDateRange={setCustomDateRange}
                  onTimeFilterChange={handleTimeFilterChange}
                  distinctPaths={distinctPaths}
                  homeOnlyCount={homeOnlyCount}
                  filteredCount={filteredSessionsCount}
                  totalCount={totalSessionsCount}
                  onResetFilters={handleResetAuditFilters}
                  selectedCanvasPath={selectedPath}
                  retainedMatchingCount={retainedMatchingCount}
                  retainedLoadedCount={retainedLoadedCount}
                  retainedTotalCount={retainedTotalCount}
                  retainedCountStatus={retainedCountStatus}
                />
              </div>
            </div>

            <div
              className="flex items-center gap-1.5 text-xs shrink-0 flex-wrap sm:flex-nowrap justify-start sm:justify-end"
              role="toolbar"
              aria-label="Replay and workspace actions"
            >
              {/* Compact Scrubber when Timeline is collapsed */}
              <div
                className={`overflow-hidden transition-all duration-300 ease-in-out motion-reduce:transition-none flex items-center ${
                  isTimelineCollapsed && displayedHistory.length > 0
                    ? "max-w-xs opacity-100"
                    : "max-w-0 opacity-0 pointer-events-none"
                }`}
                role="group"
                aria-label="Playback scrubber"
              >
                <div className="flex items-center gap-1 rounded-lg border border-border/80 bg-surface-subtle px-1.5 py-0.5 shrink-0">
                  <button
                    type="button"
                    onClick={handlePrevHop}
                    disabled={selectedHistoryIndex <= 0}
                    className="ui-button h-9 min-h-9 w-9 p-0"
                    title="Previous hop (←)"
                    aria-label="Previous hop"
                    data-keyboard-tooltip
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={handleTogglePlay}
                    className={`ui-button h-9 min-h-9 px-2.5 text-xs flex items-center gap-1 ${
                      isPlaying ? "border-primary bg-primary text-surface" : ""
                    }`}
                    title={isPlaying ? "Pause (Space)" : "Play (Space)"}
                    aria-label={isPlaying ? "Pause" : "Play"}
                  >
                    {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                    <span>{isPlaying ? "Pause" : "Play"}</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleNextHop}
                    disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
                    className="ui-button h-9 min-h-9 w-9 p-0"
                    title="Next hop (→)"
                    aria-label="Next hop"
                    data-keyboard-tooltip
                  >
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                  <span className="text-xs font-mono text-text-muted px-1">
                    {displayedHistoryMetrics.selectedNumber}/{displayedHistoryMetrics.totalItems}
                  </span>
                </div>
              </div>

              {/* Workspace actions: Timeline Toggle & Fullscreen */}
              <div className="flex items-center gap-1.5 shrink-0" role="group" aria-label="Workspace views">
                {/* Toggle Timeline Collapse */}
                <button
                  type="button"
                  onClick={() => setIsTimelineCollapsed((c) => !c)}
                  className="ui-button h-9 px-2.5 text-xs flex items-center gap-1.5"
                  title={isTimelineCollapsed ? "Show timeline panel" : "Collapse timeline panel"}
                  aria-pressed={isTimelineCollapsed}
                >
                  {isTimelineCollapsed ? <PanelRightOpen className="h-3.5 w-3.5 text-primary" /> : <PanelRightClose className="h-3.5 w-3.5" />}
                  <span className="hidden sm:inline">{isTimelineCollapsed ? "Show Timeline" : "Hide Timeline"}</span>
                </button>

                {/* Fullscreen Button */}
                <button
                  type="button"
                  onClick={enterAuditFullscreen}
                  data-audit-fullscreen-trigger="true"
                  className="ui-button h-9 px-2.5 text-xs flex items-center gap-1.5"
                  title="Enter Fullscreen Audit Studio"
                  aria-label="Enter Fullscreen Audit Studio"
                >
                  <Maximize2 className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Fullscreen</span>
                </button>
              </div>
            </div>
          </div>
          )}

          {/* A single stateful workspace changes layout props without remounting. */}
          <AuditFilesystemWorkspace
            isFullscreen={isAuditFullscreen}
            onToggleFullscreen={isAuditFullscreen ? () => setIsAuditFullscreen(false) : enterAuditFullscreen}
          />
          </div>
        </div>
      )}
    </div>
    </FilesystemContext.Provider>
  );
}
