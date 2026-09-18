// @refresh reset
"use client";

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
  Radio,
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
import { AuditFilterControls } from "./AuditFilterControls";
import { AuditSessionSelect } from "./AuditSessionSelect";
import { FilesystemTimelinePanel } from "./FilesystemTimelinePanel";
import { ResponseActionPanel } from "./ResponseActionPanel";
import { useResponseActionController } from "./ResponseActionController";
import { FilesystemContextPanel } from "./FilesystemContextPanel";
import { TimelineSplitter } from "./TimelineSplitter";
import {
  DEFAULT_STALE_THRESHOLD_MS,
  DEFAULT_TIMELINE_SIDEBAR_WIDTH,
  TIMELINE_SIDEBAR_STORAGE_KEY,
  buildAuditSnapshot,
  buildAuditUrlSearch,
  clampTimelineSidebarWidth,
  formatPageBadgeText,
  parseAuditUrlParams,
  type AuditUrlParams,
} from "./filesystemUtils";
import { TopologyCanvas } from "./TopologyCanvas";
import { useFilesystemStreaming } from "./useFilesystemStreaming";
import { useSessionCwdHistory } from "./useSessionCwdHistory";
import { useFilesystemUrlState } from "./useFilesystemUrlState";
import { useAuditReplay } from "./useAuditReplay";
import {
  deriveAuthoritativeAuditMetrics,
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

interface NavigationApplicationErrorState {
  target: AuditUrlParams;
  targetSearch: string;
  message: string;
}

type ForensicTab = "replay" | "commands" | "actions";

export function FilesystemActivity() {
  const shouldReduceMotion = useReducedMotion();

  // Selected session and path state
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [extraAuditSessions, setExtraAuditSessions] = useState<Map<string, FilesystemClosedSession | FilesystemTopologySession>>(new Map());
  const [navigationApplicationError, setNavigationApplicationError] = useState<NavigationApplicationErrorState | null>(null);

  // Fullscreen & Hybrid Replay Studio State
  const [isAuditFullscreen, setIsAuditFullscreen] = useState(false);
  const [isTimelineCollapsed, setIsTimelineCollapsed] = useState(false);
  const [timelineWidth, setTimelineWidth] = useState<number>(() => {
    if (typeof window === "undefined") return DEFAULT_TIMELINE_SIDEBAR_WIDTH;
    try {
      const saved = localStorage.getItem(TIMELINE_SIDEBAR_STORAGE_KEY);
      if (saved) {
        const parsedWidth = parseInt(saved, 10);
        if (Number.isFinite(parsedWidth)) {
          return clampTimelineSidebarWidth(parsedWidth);
        }
      }
    } catch {
      // ignore
    }
    return DEFAULT_TIMELINE_SIDEBAR_WIDTH;
  });
  const [isDraggingTimeline, setIsDraggingTimeline] = useState(false);
  const [showFailedAttempts, setShowFailedAttempts] = useState(true);
  const [activeForensicTab, setActiveForensicTab] = useState<ForensicTab>("replay");

  // Cross-cutting refs
  const selectedSessionIdRef = useRef<string | null>(null);
  const selectedLiveCwdRef = useRef<string | null>(null);
  const isMountedRef = useRef(false);
  const auditDialogRef = useRef<HTMLDivElement | null>(null);
  const focusBeforeFullscreenRef = useRef<HTMLElement | null>(null);
  const [remoteAuditLookupManager] = useState(() => {
    const initialView =
      typeof window !== "undefined" && parseAuditUrlParams(window.location.search).view === "audit"
        ? "audit"
        : "live";
    const initialParsed = typeof window !== "undefined" ? parseAuditUrlParams(window.location.search) : null;
    return new RemoteAuditLookupCoordinator({
      initialViewMode: initialView,
      initialSessionId: initialParsed?.sessionId ?? null,
      initialTargetHopId: initialParsed?.hop ?? null,
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
  useEffect(() => {
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem(TIMELINE_SIDEBAR_STORAGE_KEY, String(timelineWidth));
      } catch {
        // ignore
      }
    }
  }, [timelineWidth]);

  // Prevent text selection and preserve resize cursor during drag
  useEffect(() => {
    if (isDraggingTimeline) {
      document.body.style.userSelect = "none";
      document.body.style.cursor = "col-resize";
    } else {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    }
    return () => {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [isDraggingTimeline]);

  // Draggable splitter mouse handler (relative delta formula)
  const handleSplitterMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingTimeline(true);
    const startX = e.clientX;
    const startWidth = timelineWidth;

    const onMouseMove = (moveEvent: MouseEvent) => {
      const deltaX = startX - moveEvent.clientX;
      setTimelineWidth(clampTimelineSidebarWidth(startWidth + deltaX, window.innerWidth));
    };

    const onMouseUp = () => {
      setIsDraggingTimeline(false);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  }, [timelineWidth]);

  const handleResetTimelineWidth = useCallback(() => {
    setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
  }, []);

  const handleSplitterKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr + 24, window.innerWidth));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr - 24, window.innerWidth));
    } else if (e.key === "Enter" || e.key === " " || e.key === "Home") {
      e.preventDefault();
      setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
    }
  }, []);

  // Streaming & snapshot management hook
  const {
    snapshot,
    regionStatus,
    streamState,
    isHydrated,
    telemetryAgeMs,
    snapshotReceiptAgeMs,
    retrievalAgeMs,
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
    navigationCoordinator,
  } = useFilesystemUrlState({
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
    pacingMode,
    displayedHistory,
    selectedHistoryIndex,
    displayedHistoryMetrics,
    isAnchoredSelected,
    hopTimeMetrics,
    sessionTimeSummary,
    activeHop,
    handlePrevHop,
    handleNextHop,
    handleTogglePlay,
    handlePause,
    handleToggleSpeed,
    handleTogglePacingMode,
    replayTimeline,
  } = useAuditReplay({
    viewMode,
    history,
    anchoredHop,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    showFailedAttempts,
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
      viewMode,
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
      // If the active session actually changed its working directory, follow the new CWD.
      if (liveCwdChanged && selectedLiveSession?.cwdState.path && data.nodes.some((node) => node.path === selectedLiveSession.cwdState.path)) {
        return selectedLiveSession.cwdState.path;
      }
      // Otherwise, preserve the user's manual inspection target if it still exists in the graph.
      const valid = current && data.nodes.some((node) => node.path === current);
      if (valid) return current;
      return selectedLiveSession?.cwdState.path ?? data.sessions[0]?.cwdState.path ?? data.nodes[0]?.path ?? null;
    });
  }, [extraAuditSessions, viewMode, setExpiredSessionId, requestedSessionIdRef, requestedHopRef, remoteAuditLookupManager]);

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

  const hasActiveFilters = hideHomeOnly || targetPathFilter !== null;

  const handleResetAuditFilters = useCallback(() => {
    navigationCoordinator.userResetFilters();
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
    if (filteredSessionsCount === 0) {
      return `0 of ${totalSessionsCount} sessions match the active filter criteria. This session is pinned outside the result set.`;
    }
    if (isSelectedFilteredOut) {
      return `This session is pinned outside the active filter criteria (${filteredSessionsCount} matching session${filteredSessionsCount === 1 ? "" : "s"} available).`;
    }
    return "All historical directories touched by this session are preserved on the canvas.";
  }, [selectedSession, filteredSessionsCount, totalSessionsCount, isSelectedFilteredOut]);

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

  const handleUserSelectSession = useCallback(
    (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => {
      navigationCoordinator.userSelectSession(sessionId, sessionObj);
    },
    [navigationCoordinator],
  );

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

  return (
    <div className="space-y-5 pb-10 sm:pb-14">
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

      {/* Mode 1: Live Global Topology Mode */}
      {viewMode === "live" ? (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem] xl:items-start">
          <div className="min-w-0">
            <TopologyCanvas
              snapshot={snapshot}
              regionStatus={regionStatus}
              streamState={streamState}
              freshnessState={freshnessState}
              telemetryAgeMs={telemetryAgeMs}
              snapshotReceiptAgeMs={snapshotReceiptAgeMs}
              retrievalAgeMs={retrievalAgeMs}
              selectedSessionId={selectedSessionId}
              selectedPath={selectedPath}
              onSelectSession={selectSession}
              onSelectPath={selectPath}
              onRefresh={refresh}
              onReconnect={handleReconnect}
              staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
            />
          </div>

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
      ) : isAuditFullscreen ? (
        /* Mode 2 Fullscreen: Dedicated Forensic Replay Cockpit (Hybrid 70/30 with Collapse) */
        <div
          ref={auditDialogRef}
          role="dialog"
          aria-modal="true"
          aria-label="Audit Replay Studio Fullscreen"
          tabIndex={-1}
          className="fixed inset-0 z-50 flex flex-col bg-surface-subtle p-2.5 sm:p-3.5 gap-2.5 overflow-hidden text-text"
        >
          {/* Studio Top Navigation Bar */}
          <header className="grid shrink-0 grid-cols-1 items-start gap-3 rounded-xl border border-border bg-surface px-4 py-2.5 shadow-xs xl:grid-cols-[minmax(0,1fr)_auto]">
            <div
              className="flex min-w-0 flex-wrap items-center gap-2.5"
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
                  hasActiveFilters={hideHomeOnly || targetPathFilter !== null}
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
                  status={auditStatus}
                  errorMessage={auditErrorMessage}
                  onRetry={retryInitialDirectory}
                />
                <AuditFilterControls
                  hideHomeOnly={hideHomeOnly}
                  onToggleHideHomeOnly={handleToggleHideHomeOnly}
                  targetPath={targetPathFilter}
                  onSelectTargetPath={handleSelectTargetPath}
                  distinctPaths={distinctPaths}
                  homeOnlyCount={homeOnlyCount}
                  filteredCount={filteredSessionsCount}
                  totalCount={totalSessionsCount}
                  onResetFilters={handleResetAuditFilters}
                  selectedCanvasPath={selectedPath}
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

          {/* Main Studio Workspace */}
          <div className="min-h-0 flex-1 flex overflow-hidden">
            {/* Left Canvas: Flex-1 fills available width smoothly */}
            <div className="min-w-0 flex-1 h-full flex flex-col">
              {expiredSessionId ? (
                <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-danger-border bg-danger-subtle px-3 py-2 text-xs text-text">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
                    <span>
                      <strong>Requested audit session is no longer available:</strong> Session{" "}
                      <span className="font-mono font-semibold text-text">{expiredSessionId}</span> has expired or was not found in retained telemetry.
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {allSessions.length > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          const first = allSessions[0];
                          setExpiredSessionId(null);
                          if (first) {
                            handleUserSelectSession(first.sessionId);
                          }
                        }}
                        className="rounded border border-primary-border bg-primary px-2 py-0.5 text-xs font-semibold text-surface hover:bg-primary/90 transition-colors"
                      >
                        View latest available session
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        setExpiredSessionId(null);
                        switchViewMode("live");
                      }}
                      className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                    >
                      Return to live view
                    </button>
                  </div>
                </div>
              ) : hasActiveFilters && (isSelectedFilteredOut || filteredSessionsCount === 0) ? (
                <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-warning-border bg-warning-subtle px-3 py-2 text-xs text-text">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                    <span>
                      {filteredSessionsCount === 0 ? (
                        <>
                          <strong>0 of {totalSessionsCount} sessions match filter</strong>
                          {targetPathFilter ? ` ("${targetPathFilter}")` : ""}
                          {hideHomeOnly ? " [excluding /home]" : ""}.
                          {selectedSession ? (
                            <span className="text-text-muted ml-1">
                              Showing previously selected session <span className="font-mono font-semibold text-text">{selectedSession.sourceIp}</span> pinned outside result set.
                            </span>
                          ) : null}
                        </>
                      ) : (
                        <>
                          <strong>Pinned outside filter:</strong> Session <span className="font-mono font-semibold text-text">{selectedSession?.sourceIp}</span> does not match active filter criteria. {filteredSessionsCount} other {filteredSessionsCount === 1 ? "session matches" : "sessions match"}.
                        </>
                      )}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {filteredSessionsCount > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          const first = filteredActiveSessions[0] ?? filteredClosedSessions[0];
                          if (first) handleUserSelectSession(first.sessionId);
                        }}
                        className="rounded border border-primary-border bg-primary-subtle px-2 py-0.5 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
                      >
                        Switch to match
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={handleResetAuditFilters}
                      className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                    >
                      Reset filters
                    </button>
                    {selectedSession && filteredSessionsCount === 0 && (
                      <button
                        type="button"
                        onClick={handleClearSelection}
                        className="rounded border border-border bg-surface px-2 py-0.5 text-xs text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                      >
                        Clear selection
                      </button>
                    )}
                  </div>
                </div>
              ) : null}
              <TopologyCanvas
                snapshot={auditSnapshot ?? snapshot}
                regionStatus={regionStatus}
                streamState={streamState}
                freshnessState={freshnessState}
                telemetryAgeMs={telemetryAgeMs}
                snapshotReceiptAgeMs={snapshotReceiptAgeMs}
                retrievalAgeMs={retrievalAgeMs}
                selectedSessionId={selectedSessionId}
                selectedPath={selectedPath}
                activeHop={activeHop}
                hopDurationMs={playbackSpeed}
                title={auditCanvasTitle}
                subtitle={auditCanvasSubtitle}
                onSelectSession={handleUserSelectSession}
                onSelectPath={selectPath}
                isExpanded={isAuditFullscreen}
                onToggleExpand={() => setIsAuditFullscreen(false)}
                onRefresh={refresh}
                onReconnect={handleReconnect}
                staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
                isAuditMode={true}
                isResizingContainer={isDraggingTimeline}
                className="h-full flex-1 min-h-0"
              />
            </div>

            {/* Draggable Splitter Handle */}
            {!isTimelineCollapsed && (
              <TimelineSplitter
                isDragging={isDraggingTimeline}
                width={timelineWidth}
                onMouseDown={handleSplitterMouseDown}
                onDoubleClick={handleResetTimelineWidth}
                onKeyDown={handleSplitterKeyDown}
                className="hidden sm:flex"
              />
            )}

            <FilesystemTimelinePanel
              collapsed={isTimelineCollapsed}
              isDragging={isDraggingTimeline}
              width={timelineWidth}
              variant="fullscreen"
                  selectedSession={selectedSession}
                  sessionIsLive={Boolean(selectedSessionId && snapshot?.sessions.some((session) => session.sessionId === selectedSessionId))}
                  history={history}
                  anchoredHop={anchoredHop}
                  historyStatus={historyStatus}
                  historyCursor={historyCursor}
                  historyTotalItems={historyTotalItems}
                  historyTotalSuccessfulItems={historyTotalSuccessfulItems}
                  historyComplete={historyComplete}
                  replayTimeline={replayTimeline}
                  selectedHistoryEventId={selectedHistoryEventId}
                  activeTab={activeForensicTab}
                  onTabChange={setActiveForensicTab}
                  responsePanel={responsePanel}
                  hopResolutionStatus={hopResolutionStatus}
                  requestedHop={requestedHop}
                  onClearHop={clearRequestedHop}
                  onShowLatestHop={selectLatestHop}
                  onSelectHistoryEventId={handleSelectHistoryEventId}
                  onLoadEarlier={() => {
                    if (selectedSessionId) void loadHistory(selectedSessionId, historyCursor, true);
                  }}
                  isPlaying={isPlaying}
                  onTogglePlay={handleTogglePlay}
                  onPause={handlePause}
                  playbackSpeed={playbackSpeed}
                  onToggleSpeed={handleToggleSpeed}
                  pacingMode={pacingMode}
                  onTogglePacingMode={handleTogglePacingMode}
                  showFailedAttempts={showFailedAttempts}
                  onToggleShowFailedAttempts={setShowFailedAttempts}
                  displayedHistory={displayedHistory}
                  selectedHistoryIndex={selectedHistoryIndex}
                  displayedHistoryMetrics={displayedHistoryMetrics}
                  isAnchoredSelected={isAnchoredSelected}
                  hopTimeMetrics={hopTimeMetrics}
                  sessionTimeSummary={sessionTimeSummary}
            />
          </div>
        </div>
      ) : (
        /* Mode 2: Session Forensics & Replay Mode (Side-by-Side In-Page View) */
        <div className="space-y-4">
          {/* Target Session Selector & Action Bar (Structured Responsive Toolbar) */}
          <div
            className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 rounded-xl border border-border bg-surface px-3 py-2 shadow-xs"
            role="toolbar"
            aria-label="Audit session and replay toolbar"
          >
            <div
              className="flex flex-wrap items-center gap-2 min-w-0"
              role="group"
              aria-label="Audited session and filter controls"
            >
              <AuditSessionSelect
                sessions={filteredActiveSessions}
                recentClosedSessions={filteredClosedSessions}
                selectedSessionId={selectedSessionId}
                onSelectSession={handleUserSelectSession}
                totalCount={totalSessionsCount}
                hasActiveFilters={hideHomeOnly || targetPathFilter !== null}
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
                status={auditStatus}
                errorMessage={auditErrorMessage}
                onRetry={retryInitialDirectory}
              />
              <div className="h-4 w-px bg-border hidden sm:block shrink-0" aria-hidden="true" />
              <AuditFilterControls
                hideHomeOnly={hideHomeOnly}
                onToggleHideHomeOnly={handleToggleHideHomeOnly}
                targetPath={targetPathFilter}
                onSelectTargetPath={handleSelectTargetPath}
                distinctPaths={distinctPaths}
                homeOnlyCount={homeOnlyCount}
                filteredCount={filteredSessionsCount}
                totalCount={totalSessionsCount}
                onResetFilters={handleResetAuditFilters}
                selectedCanvasPath={selectedPath}
              />
            </div>

            <div
              className="flex items-center gap-2 text-xs shrink-0 flex-wrap sm:flex-nowrap justify-start sm:justify-end"
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

          {/* Side-by-Side Audit Layout */}
          <div className="flex flex-col lg:flex-row items-stretch lg:h-[600px] xl:h-[660px]">
            <div className="min-w-0 flex-1 h-full flex flex-col min-h-[480px] lg:min-h-0">
              {expiredSessionId ? (
                <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-danger-border bg-danger-subtle px-3 py-2 text-xs text-text">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
                    <span>
                      <strong>Requested audit session is no longer available:</strong> Session{" "}
                      <span className="font-mono font-semibold text-text">{expiredSessionId}</span> has expired or was not found in retained telemetry.
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {allSessions.length > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          const first = allSessions[0];
                          setExpiredSessionId(null);
                          if (first) {
                            handleUserSelectSession(first.sessionId);
                          }
                        }}
                        className="rounded border border-primary-border bg-primary px-2 py-0.5 text-xs font-semibold text-surface hover:bg-primary/90 transition-colors"
                      >
                        View latest available session
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        setExpiredSessionId(null);
                        switchViewMode("live");
                      }}
                      className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                    >
                      Return to live view
                    </button>
                  </div>
                </div>
              ) : hasActiveFilters && (isSelectedFilteredOut || filteredSessionsCount === 0) ? (
                <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-warning-border bg-warning-subtle px-3 py-2 text-xs text-text">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                    <span>
                      {filteredSessionsCount === 0 ? (
                        <>
                          <strong>0 of {totalSessionsCount} sessions match filter</strong>
                          {targetPathFilter ? ` ("${targetPathFilter}")` : ""}
                          {hideHomeOnly ? " [excluding /home]" : ""}.
                          {selectedSession ? (
                            <span className="text-text-muted ml-1">
                              Showing previously selected session <span className="font-mono font-semibold text-text">{selectedSession.sourceIp}</span> pinned outside result set.
                            </span>
                          ) : null}
                        </>
                      ) : (
                        <>
                          <strong>Pinned outside filter:</strong> Session <span className="font-mono font-semibold text-text">{selectedSession?.sourceIp}</span> does not match active filter criteria. {filteredSessionsCount} other {filteredSessionsCount === 1 ? "session matches" : "sessions match"}.
                        </>
                      )}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {filteredSessionsCount > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          const first = filteredActiveSessions[0] ?? filteredClosedSessions[0];
                          if (first) handleUserSelectSession(first.sessionId);
                        }}
                        className="rounded border border-primary-border bg-primary-subtle px-2 py-0.5 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
                      >
                        Switch to match
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={handleResetAuditFilters}
                      className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                    >
                      Reset filters
                    </button>
                    {selectedSession && filteredSessionsCount === 0 && (
                      <button
                        type="button"
                        onClick={handleClearSelection}
                        className="rounded border border-border bg-surface px-2 py-0.5 text-xs text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
                      >
                        Clear selection
                      </button>
                    )}
                  </div>
                </div>
              ) : null}
              <TopologyCanvas
                snapshot={auditSnapshot ?? snapshot}
                regionStatus={regionStatus}
                streamState={streamState}
                freshnessState={freshnessState}
                telemetryAgeMs={telemetryAgeMs}
                snapshotReceiptAgeMs={snapshotReceiptAgeMs}
                retrievalAgeMs={retrievalAgeMs}
                selectedSessionId={selectedSessionId}
                selectedPath={selectedPath}
                activeHop={activeHop}
                hopDurationMs={playbackSpeed}
                title={auditCanvasTitle}
                subtitle={auditCanvasSubtitle}
                onSelectSession={handleUserSelectSession}
                onSelectPath={selectPath}
                isExpanded={false}
                onToggleExpand={enterAuditFullscreen}
                onRefresh={refresh}
                onReconnect={handleReconnect}
                staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
                isAuditMode={true}
                isResizingContainer={isDraggingTimeline}
                className="h-full flex-1 min-h-0"
              />
            </div>

            {/* Draggable Splitter Handle (desktop only) */}
            {!isTimelineCollapsed && (
              <TimelineSplitter
                isDragging={isDraggingTimeline}
                width={timelineWidth}
                onMouseDown={handleSplitterMouseDown}
                onDoubleClick={handleResetTimelineWidth}
                onKeyDown={handleSplitterKeyDown}
                className="hidden lg:flex"
              />
            )}

            <FilesystemTimelinePanel
              collapsed={isTimelineCollapsed}
              isDragging={isDraggingTimeline}
              width={timelineWidth}
              variant="page"
                  selectedSession={selectedSession}
                  sessionIsLive={Boolean(selectedSessionId && snapshot?.sessions.some((session) => session.sessionId === selectedSessionId))}
                  history={history}
                  anchoredHop={anchoredHop}
                  historyStatus={historyStatus}
                  historyCursor={historyCursor}
                  historyTotalItems={historyTotalItems}
                  historyTotalSuccessfulItems={historyTotalSuccessfulItems}
                  historyComplete={historyComplete}
                  replayTimeline={replayTimeline}
                  selectedHistoryEventId={selectedHistoryEventId}
                  activeTab={activeForensicTab}
                  onTabChange={setActiveForensicTab}
                  responsePanel={responsePanel}
                  hopResolutionStatus={hopResolutionStatus}
                  requestedHop={requestedHop}
                  onClearHop={clearRequestedHop}
                  onShowLatestHop={selectLatestHop}
                  onSelectHistoryEventId={handleSelectHistoryEventId}
                  onLoadEarlier={() => {
                    if (selectedSessionId) void loadHistory(selectedSessionId, historyCursor, true);
                  }}
                  isPlaying={isPlaying}
                  onTogglePlay={handleTogglePlay}
                  onPause={handlePause}
                  playbackSpeed={playbackSpeed}
                  onToggleSpeed={handleToggleSpeed}
                  pacingMode={pacingMode}
                  onTogglePacingMode={handleTogglePacingMode}
                  showFailedAttempts={showFailedAttempts}
                  onToggleShowFailedAttempts={setShowFailedAttempts}
                  displayedHistory={displayedHistory}
                  selectedHistoryIndex={selectedHistoryIndex}
                  displayedHistoryMetrics={displayedHistoryMetrics}
                  isAnchoredSelected={isAnchoredSelected}
                  hopTimeMetrics={hopTimeMetrics}
                  sessionTimeSummary={sessionTimeSummary}
            />
          </div>
        </div>
      )}
    </div>
  );
}
