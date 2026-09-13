// @refresh reset
"use client";

import {
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

import type { RegionStatus } from "@/components/ui/RegionState";
import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";
import { AuditFilterControls } from "./AuditFilterControls";
import { AuditSessionSelect } from "./AuditSessionSelect";
import { CwdRouteHistory } from "./CwdRouteHistory";
import { FilesystemContextPanel } from "./FilesystemContextPanel";
import { TimelineSplitter } from "./TimelineSplitter";
import {
  DEFAULT_TIMELINE_SIDEBAR_WIDTH,
  MAX_TIMELINE_SIDEBAR_WIDTH,
  MIN_TIMELINE_SIDEBAR_WIDTH,
  TIMELINE_SIDEBAR_STORAGE_KEY,
  buildAuditSnapshot,
  getDistinctSessionPaths,
  isHistoryPage,
  isHomeOnlySession,
  isSnapshot,
  sessionTouchesPath,
  type ActiveHopRoute,
  type DistinctPathOption,
  type StreamState,
} from "./filesystemUtils";
import { TopologyCanvas } from "./TopologyCanvas";

export function FilesystemActivity() {
  const shouldReduceMotion = useReducedMotion();
  const [viewMode, setViewMode] = useState<"live" | "audit">("live");
  const [snapshot, setSnapshot] = useState<FilesystemTopologySnapshot | null>(null);
  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [history, setHistory] = useState<SessionCwdHistoryEvent[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyStatus, setHistoryStatus] = useState<RegionStatus>("loading");
  const [selectedHistoryEventId, setSelectedHistoryEventId] = useState<string | null>(null);
  const [isHydrated, setIsHydrated] = useState(false);

  // Audit Mode Filter State
  const [hideHomeOnly, setHideHomeOnly] = useState(false);
  const [targetPathFilter, setTargetPathFilter] = useState<string | null>(null);

  // Fullscreen & Hybrid Replay Studio State
  const [isAuditFullscreen, setIsAuditFullscreen] = useState(false);
  const [isTimelineCollapsed, setIsTimelineCollapsed] = useState(false);
  const [timelineWidth, setTimelineWidth] = useState<number>(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
  const [isDraggingTimeline, setIsDraggingTimeline] = useState(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1400);
  const [showFailedAttempts, setShowFailedAttempts] = useState(true);

  const historyRequest = useRef<{ generation: number; sessionId: string; controller: AbortController } | null>(null);
  const latestSnapshotAt = useRef(0);
  const selectedSessionIdRef = useRef<string | null>(null);
  const selectedLiveCwdRef = useRef<string | null>(null);
  const auditDialogRef = useRef<HTMLDivElement | null>(null);
  const focusBeforeFullscreenRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    selectedSessionIdRef.current = selectedSessionId;
  }, [selectedSessionId]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsHydrated(true);
      if (typeof window !== "undefined") {
        const params = new URLSearchParams(window.location.search);
        const urlView = params.get("view");
        const urlSessionId = params.get("sessionId");
        if (urlView === "audit") {
          setViewMode("audit");
        }
        if (urlSessionId) {
          selectedSessionIdRef.current = urlSessionId;
          setSelectedSessionId(urlSessionId);
        }
        const urlHideHome = params.get("hideHome");
        if (urlHideHome === "1" || urlHideHome === "true") {
          setHideHomeOnly(true);
        }
        const urlTargetPath = params.get("targetPath");
        if (urlTargetPath) {
          setTargetPathFilter(urlTargetPath);
        }

        try {
          const saved = localStorage.getItem(TIMELINE_SIDEBAR_STORAGE_KEY);
          if (saved) {
            const parsed = parseInt(saved, 10);
            if (!Number.isNaN(parsed)) {
              setTimelineWidth(Math.max(MIN_TIMELINE_SIDEBAR_WIDTH, Math.min(MAX_TIMELINE_SIDEBAR_WIDTH, parsed)));
            }
          }
        } catch {
          // ignore
        }
      }
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // Persist timeline width preference
  useEffect(() => {
    if (isHydrated && typeof window !== "undefined") {
      try {
        localStorage.setItem(TIMELINE_SIDEBAR_STORAGE_KEY, String(timelineWidth));
      } catch {
        // ignore
      }
    }
  }, [timelineWidth, isHydrated]);

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
      const maxAllowed = Math.min(MAX_TIMELINE_SIDEBAR_WIDTH, Math.floor(window.innerWidth * 0.65));
      const clamped = Math.max(MIN_TIMELINE_SIDEBAR_WIDTH, Math.min(maxAllowed, startWidth + deltaX));
      setTimelineWidth(clamped);
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
      setTimelineWidth((curr) => Math.min(MAX_TIMELINE_SIDEBAR_WIDTH, curr + 24));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setTimelineWidth((curr) => Math.max(MIN_TIMELINE_SIDEBAR_WIDTH, curr - 24));
    } else if (e.key === "Enter" || e.key === " " || e.key === "Home") {
      e.preventDefault();
      setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
    }
  }, []);

  const applySnapshot = useCallback((data: FilesystemTopologySnapshot) => {
    const timestamp = Date.parse(data.generatedAt);
    if (Number.isFinite(timestamp) && timestamp < latestSnapshotAt.current) return;
    if (Number.isFinite(timestamp)) latestSnapshotAt.current = timestamp;

    setSnapshot(data);
    setRegionStatus("ready");

    const knownSessions = [...data.sessions, ...data.recentClosedSessions];
    const currentSessionId = selectedSessionIdRef.current;
    const nextSessionId = knownSessions.some((session) => session.sessionId === currentSessionId)
      ? currentSessionId
      : data.sessions[0]?.sessionId ?? data.recentClosedSessions[0]?.sessionId ?? null;
    const selectedLiveSession = data.sessions.find((session) => session.sessionId === nextSessionId) ?? null;

    selectedSessionIdRef.current = nextSessionId;
    setSelectedSessionId(nextSessionId);

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
  }, []);

  const refresh = useCallback(async () => {
    setRegionStatus((current) => (snapshot ? "refreshing" : current === "error" ? "loading" : current));
    try {
      const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
      if (!response.ok) throw new Error("Topology request failed");
      const data: unknown = await response.json();
      if (!isSnapshot(data)) throw new Error("Topology response unavailable");
      applySnapshot(data);
    } catch {
      setRegionStatus(snapshot ? "stale" : "error");
    }
  }, [applySnapshot, snapshot]);

  // SSE Stream subscription with HTTP fallback
  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    let retry: number | null = null;

    const fetchSnapshot = async () => {
      try {
        const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
        if (!response.ok) throw new Error("Topology fallback failed");
        const data: unknown = await response.json();
        if (!isSnapshot(data) || disposed) return;
        applySnapshot(data);
      } catch {
        if (!disposed) setRegionStatus((current) => (current === "ready" ? "stale" : "error"));
      }
    };

    const onMessage = (event: MessageEvent<string>) => {
      try {
        const message: unknown = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
        const data = (message as { data?: unknown }).data;
        if (!isSnapshot(data)) return;
        applySnapshot(data);
        setStreamState("live");
      } catch {
        /* retain the last valid topology */
      }
    };

    const connect = () => {
      source = new EventSource("/api/filesystem-topology/stream");
      source.addEventListener("snapshot", onMessage as EventListener);
      source.addEventListener("topology.update", onMessage as EventListener);
      source.onopen = () => {
        if (disposed) return;
        setIsHydrated(true);
        setStreamState("live");
      };
      source.onerror = () => {
        if (disposed || source === null) return;
        setIsHydrated(true);
        setStreamState("stale");
        source.close();
        source = null;
        void fetchSnapshot();
        retry = window.setTimeout(connect, 5_000);
      };
    };

    connect();
    return () => {
      disposed = true;
      source?.close();
      if (retry !== null) window.clearTimeout(retry);
    };
  }, [applySnapshot]);

  // CWD history pagination with cancellation
  const lastHistorySessionId = useRef<string | null>(null);
  const loadHistory = useCallback(async (sessionId: string, cursor: string | null, append = false) => {
    const generation = (historyRequest.current?.generation ?? 0) + 1;
    historyRequest.current?.controller.abort();
    const controller = new AbortController();
    historyRequest.current = { generation, sessionId, controller };
    const isNewSession = sessionId !== lastHistorySessionId.current;
    lastHistorySessionId.current = sessionId;
    if (!append && isNewSession) {
      setHistory([]);
      setHistoryCursor(null);
      setSelectedHistoryEventId(null);
    }
    setHistoryStatus(append || !isNewSession ? "refreshing" : "loading");
    try {
      const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/cwd-history${params}`, {
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("History request failed");
      const data: unknown = await response.json();
      if (!isHistoryPage(data)) throw new Error("History response unavailable");
      const active = historyRequest.current;
      if (!active || active.generation !== generation || active.sessionId !== sessionId) return;
      setHistory((current) => (append ? [...current, ...data.items] : data.items));
      setHistoryCursor(data.nextCursor);
      setHistoryStatus("ready");
    } catch {
      if (controller.signal.aborted || historyRequest.current?.generation !== generation) return;
      setHistoryStatus("error");
    }
  }, []);

  const allSessions = useMemo(
    () => [...(snapshot?.sessions ?? []), ...(snapshot?.recentClosedSessions ?? [])],
    [snapshot],
  );
  const sessionById = useMemo(() => new Map(allSessions.map((s) => [s.sessionId, s])), [allSessions]);
  const selectedSession = useMemo(() => sessionById.get(selectedSessionId ?? "") ?? null, [selectedSessionId, sessionById]);
  const selectedClosedSession = useMemo(
    () => snapshot?.recentClosedSessions.find((s) => s.sessionId === selectedSessionId) ?? null,
    [selectedSessionId, snapshot],
  );
  const selectedNode = useMemo(
    () => snapshot?.nodes.find((n) => n.path === selectedPath) ?? null,
    [selectedPath, snapshot],
  );
  const selectedNodeLiveSessionCount = useMemo(
    () => (selectedPath ? (snapshot?.sessions.filter((session) => session.cwdState.path === selectedPath).length ?? 0) : 0),
    [selectedPath, snapshot],
  );

  const distinctPaths: DistinctPathOption[] = useMemo(() => {
    return getDistinctSessionPaths(
      snapshot?.nodes ?? [],
      snapshot?.sessions ?? [],
      snapshot?.recentClosedSessions ?? [],
    );
  }, [snapshot]);

  const {
    filteredActiveSessions,
    filteredClosedSessions,
    homeOnlyCount,
    totalSessionsCount,
    filteredSessionsCount,
  } = useMemo(() => {
    const allActive = snapshot?.sessions ?? [];
    const allClosed = snapshot?.recentClosedSessions ?? [];
    const allNodes = snapshot?.nodes ?? [];

    let homeCount = 0;
    for (const s of allActive) {
      if (isHomeOnlySession(s, allNodes)) homeCount++;
    }
    for (const s of allClosed) {
      if (isHomeOnlySession(s, allNodes)) homeCount++;
    }

    const filterFn = (s: FilesystemTopologySession | FilesystemClosedSession) => {
      if (hideHomeOnly && isHomeOnlySession(s, allNodes)) {
        return false;
      }
      if (targetPathFilter && !sessionTouchesPath(s, targetPathFilter, allNodes)) {
        return false;
      }
      return true;
    };

    const filteredActive = allActive.filter(filterFn);
    const filteredClosed = allClosed.filter(filterFn);
    const total = allActive.length + allClosed.length;
    const filtered = filteredActive.length + filteredClosed.length;

    return {
      filteredActiveSessions: filteredActive,
      filteredClosedSessions: filteredClosed,
      homeOnlyCount: homeCount,
      totalSessionsCount: total,
      filteredSessionsCount: filtered,
    };
  }, [snapshot, hideHomeOnly, targetPathFilter]);

  const handleResetAuditFilters = useCallback(() => {
    setHideHomeOnly(false);
    setTargetPathFilter(null);
  }, []);

  // Sync URL query params with audit filters
  useEffect(() => {
    if (viewMode !== "audit" || typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (hideHomeOnly) {
      url.searchParams.set("hideHome", "1");
    } else {
      url.searchParams.delete("hideHome");
    }
    if (targetPathFilter) {
      url.searchParams.set("targetPath", targetPathFilter);
    } else {
      url.searchParams.delete("targetPath");
    }
    window.history.replaceState(null, "", url.toString());
  }, [viewMode, hideHomeOnly, targetPathFilter]);

  // Reload CWD route when a new source event arrives for the selected session
  useEffect(() => {
    if (!selectedSessionId) {
      historyRequest.current?.controller.abort();
      return;
    }
    const request = window.setTimeout(() => {
      void loadHistory(selectedSessionId, null);
    }, 0);
    return () => {
      window.clearTimeout(request);
      if (historyRequest.current?.sessionId === selectedSessionId) historyRequest.current.controller.abort();
    };
  }, [loadHistory, selectedSession?.cwdState.sourceEventId, selectedSessionId]);

  const selectSession = useCallback(
    (sessionId: string) => {
      const isDifferentSession = sessionId !== selectedSessionIdRef.current;
      const session = sessionById.get(sessionId);
      historyRequest.current?.controller.abort();
      if (isDifferentSession) {
        setHistory([]);
        setHistoryCursor(null);
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
    [sessionById, snapshot?.nodes, loadHistory],
  );

  const handleToggleHideHomeOnly = useCallback(() => {
    setHideHomeOnly((prev) => {
      const next = !prev;
      if (next && selectedSessionId) {
        const allNodes = snapshot?.nodes ?? [];
        const currentSession = sessionById.get(selectedSessionId);
        if (currentSession && isHomeOnlySession(currentSession, allNodes)) {
          const firstNonHome = allSessions.find((s) => {
            if (isHomeOnlySession(s, allNodes)) return false;
            if (targetPathFilter && !sessionTouchesPath(s, targetPathFilter, allNodes)) return false;
            return true;
          });
          if (firstNonHome) {
            selectSession(firstNonHome.sessionId);
          }
        }
      }
      return next;
    });
  }, [selectedSessionId, snapshot?.nodes, sessionById, allSessions, targetPathFilter, selectSession]);

  const handleSelectTargetPath = useCallback(
    (path: string | null) => {
      setTargetPathFilter(path);
      if (path && selectedSessionId) {
        const allNodes = snapshot?.nodes ?? [];
        const currentSession = sessionById.get(selectedSessionId);
        if (currentSession && !sessionTouchesPath(currentSession, path, allNodes)) {
          const firstMatching = allSessions.find((s) => {
            if (hideHomeOnly && isHomeOnlySession(s, allNodes)) return false;
            if (!sessionTouchesPath(s, path, allNodes)) return false;
            return true;
          });
          if (firstMatching) {
            selectSession(firstMatching.sessionId);
          }
        }
      }
    },
    [selectedSessionId, snapshot?.nodes, sessionById, allSessions, hideHomeOnly, selectSession],
  );

  // Decoupled directory selection: inspects directory metadata without destroying the currently audited session
  const selectPath = (path: string | null) => {
    setSelectedPath(path);
  };

  const switchViewMode = useCallback(
    (mode: "live" | "audit", targetSessionId?: string) => {
      if (mode === "live") {
        setIsAuditFullscreen(false);
        setIsPlaying(false);
      }
      setViewMode(mode);
      const sid =
        targetSessionId ??
        selectedSessionIdRef.current ??
        snapshot?.sessions[0]?.sessionId ??
        snapshot?.recentClosedSessions[0]?.sessionId ??
        null;
      if (sid) {
        selectSession(sid);
      }
      if (typeof window !== "undefined") {
        const url = new URL(window.location.href);
        if (mode === "audit") {
          url.searchParams.set("view", "audit");
          if (sid) url.searchParams.set("sessionId", sid);
          if (hideHomeOnly) url.searchParams.set("hideHome", "1");
          else url.searchParams.delete("hideHome");
          if (targetPathFilter) url.searchParams.set("targetPath", targetPathFilter);
          else url.searchParams.delete("targetPath");
        } else {
          url.searchParams.delete("view");
          url.searchParams.delete("sessionId");
          url.searchParams.delete("hideHome");
          url.searchParams.delete("targetPath");
        }
        window.history.replaceState(null, "", url.toString());
      }
    },
    [selectSession, snapshot?.sessions, snapshot?.recentClosedSessions, hideHomeOnly, targetPathFilter],
  );

  const auditSnapshot = useMemo(() => {
    if (viewMode !== "audit") return null;
    return buildAuditSnapshot(snapshot, selectedSession, history);
  }, [viewMode, snapshot, selectedSession, history]);

  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);

  const displayedHistory = useMemo(() => {
    if (showFailedAttempts) return chronologicalHistory;
    return chronologicalHistory.filter((e) => e.action !== "failed_change");
  }, [chronologicalHistory, showFailedAttempts]);

  const selectedHistoryIndex = useMemo(() => {
    if (!displayedHistory.length) return -1;
    const index = displayedHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : displayedHistory.length - 1;
  }, [displayedHistory, selectedHistoryEventId]);

  const activeHop: ActiveHopRoute | null = useMemo(() => {
    if (selectedHistoryIndex < 0 || !displayedHistory[selectedHistoryIndex]) return null;
    const currentEvent = displayedHistory[selectedHistoryIndex];
    const isFailed = currentEvent.action === "failed_change";
    const visitedStepMap: Record<string, number> = {};
    for (let i = 0; i <= selectedHistoryIndex; i++) {
      const ev = displayedHistory[i];
      if (ev.action !== "failed_change" && ev.toPath && visitedStepMap[ev.toPath] === undefined) {
        visitedStepMap[ev.toPath] = i + 1;
      }
    }
    return {
      eventId: currentEvent.id,
      fromPath: currentEvent.fromPath,
      toPath: isFailed ? currentEvent.fromPath : currentEvent.toPath,
      action: currentEvent.action,
      status: currentEvent.status,
      at: currentEvent.at,
      stepIndex: selectedHistoryIndex,
      totalSteps: displayedHistory.length,
      visitedPaths: Object.keys(visitedStepMap),
      visitedStepMap,
      isFailedAttempt: isFailed,
    };
  }, [displayedHistory, selectedHistoryIndex]);

  const handlePrevHop = useCallback(() => {
    setIsPlaying(false);
    if (selectedHistoryIndex > 0) {
      setSelectedHistoryEventId(displayedHistory[selectedHistoryIndex - 1]?.id ?? null);
    }
  }, [displayedHistory, selectedHistoryIndex]);

  const handleNextHop = useCallback(() => {
    setIsPlaying(false);
    if (selectedHistoryIndex >= 0 && selectedHistoryIndex < displayedHistory.length - 1) {
      setSelectedHistoryEventId(displayedHistory[selectedHistoryIndex + 1]?.id ?? null);
    }
  }, [displayedHistory, selectedHistoryIndex]);

  const handleTogglePlay = useCallback(() => {
    if (selectedHistoryIndex >= displayedHistory.length - 1) {
      setSelectedHistoryEventId(displayedHistory[0]?.id ?? null);
    }
    setIsPlaying((prev) => !prev);
  }, [displayedHistory, selectedHistoryIndex]);

  const handlePause = useCallback(() => {
    setIsPlaying(false);
  }, []);

  const handleToggleSpeed = useCallback(() => {
    setPlaybackSpeed((current) => (current === 1400 ? 700 : 1400));
  }, []);

  const enterAuditFullscreen = useCallback(() => {
    focusBeforeFullscreenRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setIsAuditFullscreen(true);
  }, []);

  // Synchronized auto-play timer for audit mode
  useEffect(() => {
    if (viewMode !== "audit" || !isPlaying) return;

    const timer = setTimeout(() => {
      if (selectedHistoryIndex >= displayedHistory.length - 1) {
        setIsPlaying(false);
        return;
      }

      const nextIndex = selectedHistoryIndex + 1;
      const nextEvent = displayedHistory[nextIndex];
      if (nextEvent) {
        setSelectedHistoryEventId(nextEvent.id);
      } else {
        setIsPlaying(false);
      }
    }, playbackSpeed);

    return () => clearTimeout(timer);
  }, [viewMode, isPlaying, selectedHistoryIndex, displayedHistory, playbackSpeed]);

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
      {/* Header Section */}
      <section className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-text">Filesystem activity</h1>
          <p className="mt-0.5 max-w-2xl text-xs text-text-muted">
            {viewMode === "live"
              ? "Inspect observed Cowrie working-directory topology and live threat clusters."
              : "Step-by-step forensic route replay and directory timeline for audited attacker session."}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Mode Switcher Tabs */}
          <div
            className="flex items-center rounded-lg border border-border bg-surface-subtle p-0.5"
            aria-label="Filesystem views"
          >
            <button
              type="button"
              aria-pressed={viewMode === "live"}
              onClick={() => switchViewMode("live")}
              className={`flex min-h-9 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                viewMode === "live"
                  ? "bg-surface text-primary shadow-xs border border-border"
                  : "text-text-muted hover:text-text"
              }`}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              Live Topology
              {snapshot?.sessions.length ? (
                <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-xs font-mono text-text-subtle border border-border">
                  {snapshot.sessions.length}
                </span>
              ) : null}
            </button>

            <button
              type="button"
              aria-pressed={viewMode === "audit"}
              onClick={() => switchViewMode("audit")}
              className={`flex min-h-9 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                viewMode === "audit"
                  ? "bg-surface text-primary shadow-xs border border-border"
                  : "text-text-muted hover:text-text"
              }`}
            >
              <Route className="h-3.5 w-3.5" aria-hidden="true" />
              Session Audit & Replay
              {selectedSession && (
                <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-xs font-mono text-text-subtle border border-border">
                  .{selectedSession.sourceIp.split(".").pop()}
                </span>
              )}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`ui-badge ${
                streamState === "live"
                  ? "border-success-border bg-success-subtle text-success"
                  : "border-warning-border bg-warning-subtle text-warning"
              }`}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              {streamState === "live" ? "Live updates" : streamState === "connecting" ? "Connecting" : "Reconnecting"}
            </span>
            <button
              type="button"
              className="ui-button"
              onClick={() => {
                if (!isHydrated || regionStatus === "loading" || regionStatus === "refreshing") return;
                void refresh();
              }}
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
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
              selectedSessionId={selectedSessionId}
              selectedPath={selectedPath}
              onSelectSession={selectSession}
              onSelectPath={selectPath}
            />
          </div>

          <FilesystemContextPanel
            selectedSession={selectedSession}
            selectedClosedSession={selectedClosedSession}
            selectedNode={selectedNode}
            sessions={snapshot?.sessions ?? []}
            recentClosedSessions={snapshot?.recentClosedSessions ?? []}
            liveSessionCount={selectedNodeLiveSessionCount}
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
            <div className="flex min-w-0 flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-2">
                <Route className="h-4 w-4 text-primary" />
                <span className="text-sm font-semibold text-text">Audit Replay Studio</span>
              </div>
              <div className="h-4 w-px bg-border hidden sm:block" />
              <span className="text-xs text-text-subtle font-medium hidden md:inline">Audited Session:</span>
              <AuditSessionSelect
                sessions={filteredActiveSessions}
                recentClosedSessions={filteredClosedSessions}
                selectedSessionId={selectedSessionId}
                onSelectSession={selectSession}
                totalCount={totalSessionsCount}
                hasActiveFilters={hideHomeOnly || targetPathFilter !== null}
                onResetFilters={handleResetAuditFilters}
                allSessionsList={allSessions}
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
              {selectedSession && (
                <span className="font-mono text-xs text-text-subtle hidden xl:inline">
                  IP: <strong className="text-text">{selectedSession.sourceIp}</strong>
                </span>
              )}
            </div>

            {/* Stable right-side control cluster */}
            <div className="flex min-h-10 flex-wrap items-center justify-end gap-2 justify-self-end xl:flex-nowrap">
              {displayedHistory.length > 0 && (
                <div className="relative h-10 w-72 shrink-0 overflow-hidden">
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
                            Hop <strong className="text-primary">{selectedHistoryIndex + 1}</strong> of {displayedHistory.length}
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
          </header>

          {/* Main Studio Workspace */}
          <div className="min-h-0 flex-1 flex overflow-hidden">
            {/* Left Canvas: Flex-1 fills available width smoothly */}
            <div className="min-w-0 flex-1 h-full flex flex-col">
              <TopologyCanvas
                snapshot={auditSnapshot ?? snapshot}
                regionStatus={regionStatus}
                streamState={streamState}
                selectedSessionId={selectedSessionId}
                selectedPath={selectedPath}
                activeHop={activeHop}
                hopDurationMs={playbackSpeed}
                title={`Attack Trajectory: ${selectedSession?.sourceIp ?? "Session"}`}
                subtitle="All historical directories touched by this session are preserved on the canvas."
                onSelectSession={selectSession}
                onSelectPath={selectPath}
                isExpanded={isAuditFullscreen}
                onToggleExpand={() => setIsAuditFullscreen(false)}
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

            {/* Right Timeline: Smoothly collapsible & resizable sidebar */}
            <div
              inert={isTimelineCollapsed ? true : undefined}
              aria-hidden={isTimelineCollapsed}
              style={{ width: isTimelineCollapsed ? 0 : timelineWidth }}
              className={`h-full flex flex-col shrink-0 overflow-hidden ${
                isDraggingTimeline
                  ? "transition-none"
                  : "transition-[width,opacity,margin] duration-300 ease-in-out motion-reduce:transition-none"
              } ${
                isTimelineCollapsed
                  ? "opacity-0 pointer-events-none ml-0"
                  : "opacity-100 ml-2 sm:ml-2.5"
              }`}
            >
              <div
                style={{ width: timelineWidth }}
                className="h-full flex flex-col min-h-0"
              >
                <CwdRouteHistory
                  selectedSession={selectedSession}
                  history={history}
                  historyStatus={historyStatus}
                  historyCursor={historyCursor}
                  selectedHistoryEventId={selectedHistoryEventId}
                  layout="sidebar"
                  onSelectHistoryEventId={setSelectedHistoryEventId}
                  onLoadEarlier={() => {
                    if (selectedSessionId) void loadHistory(selectedSessionId, historyCursor, true);
                  }}
                  isPlaying={isPlaying}
                  onTogglePlay={handleTogglePlay}
                  onPause={handlePause}
                  playbackSpeed={playbackSpeed}
                  onToggleSpeed={handleToggleSpeed}
                  showFailedAttempts={showFailedAttempts}
                  onToggleShowFailedAttempts={setShowFailedAttempts}
                />
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Mode 2: Session Forensics & Replay Mode (Side-by-Side In-Page View) */
        <div className="space-y-4">
          {/* Target Session Selector & Action Bar (Compact Single-Row Toolbar) */}
          <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-border bg-surface px-3 py-2 shadow-xs">
            <div className="flex flex-wrap items-center gap-2">
              <AuditSessionSelect
                sessions={filteredActiveSessions}
                recentClosedSessions={filteredClosedSessions}
                selectedSessionId={selectedSessionId}
                onSelectSession={selectSession}
                totalCount={totalSessionsCount}
                hasActiveFilters={hideHomeOnly || targetPathFilter !== null}
                onResetFilters={handleResetAuditFilters}
                allSessionsList={allSessions}
              />
              <div className="h-4 w-px bg-border hidden sm:block" />
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

            <div className="flex items-center gap-1.5 text-xs">
              {/* Compact Scrubber when Timeline is collapsed */}
              <div
                className={`overflow-hidden transition-all duration-300 ease-in-out motion-reduce:transition-none flex items-center ${
                  isTimelineCollapsed && displayedHistory.length > 0
                    ? "max-w-xs opacity-100"
                    : "max-w-0 opacity-0 pointer-events-none"
                }`}
              >
                <div className="flex items-center gap-1 rounded-lg border border-border bg-surface-subtle px-1.5 py-0.5 shrink-0">
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
                    {selectedHistoryIndex + 1}/{displayedHistory.length}
                  </span>
                </div>
              </div>

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

          {/* Side-by-Side Audit Layout */}
          <div className="flex flex-col lg:flex-row items-stretch lg:h-[600px] xl:h-[660px]">
            <div className="min-w-0 flex-1 h-full flex flex-col min-h-[480px] lg:min-h-0">
              <TopologyCanvas
                snapshot={auditSnapshot ?? snapshot}
                regionStatus={regionStatus}
                streamState={streamState}
                selectedSessionId={selectedSessionId}
                selectedPath={selectedPath}
                activeHop={activeHop}
                hopDurationMs={playbackSpeed}
                title={`Attack Trajectory: ${selectedSession?.sourceIp ?? "Session"}`}
                subtitle="All historical directories touched by this session are preserved on the canvas."
                onSelectSession={selectSession}
                onSelectPath={selectPath}
                isExpanded={false}
                onToggleExpand={enterAuditFullscreen}
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

            {/* Smooth Collapsible & Resizable Sidebar */}
            <div
              inert={isTimelineCollapsed ? true : undefined}
              aria-hidden={isTimelineCollapsed}
              style={{
                ['--timeline-width' as string]: `${timelineWidth}px`,
                width: isTimelineCollapsed ? 0 : undefined,
              }}
              className={`flex flex-col shrink-0 overflow-hidden ${
                isDraggingTimeline
                  ? "transition-none"
                  : "transition-all duration-300 ease-in-out motion-reduce:transition-none"
              } ${
                isTimelineCollapsed
                  ? "max-h-0 lg:max-h-none lg:w-0 opacity-0 pointer-events-none mt-0 lg:mt-0 lg:ml-0"
                  : "max-h-[800px] lg:max-h-none w-full lg:w-[var(--timeline-width)] opacity-100 mt-4 lg:mt-0 lg:ml-2.5"
              }`}
            >
              <div
                style={{ ['--timeline-width' as string]: `${timelineWidth}px` }}
                className="w-full lg:w-[var(--timeline-width)] h-full flex flex-col min-h-0"
              >
                <CwdRouteHistory
                  selectedSession={selectedSession}
                  history={history}
                  historyStatus={historyStatus}
                  historyCursor={historyCursor}
                  selectedHistoryEventId={selectedHistoryEventId}
                  layout="sidebar"
                  onSelectHistoryEventId={setSelectedHistoryEventId}
                  onLoadEarlier={() => {
                    if (selectedSessionId) void loadHistory(selectedSessionId, historyCursor, true);
                  }}
                  isPlaying={isPlaying}
                  onTogglePlay={handleTogglePlay}
                  onPause={handlePause}
                  playbackSpeed={playbackSpeed}
                  onToggleSpeed={handleToggleSpeed}
                  showFailedAttempts={showFailedAttempts}
                  onToggleShowFailedAttempts={setShowFailedAttempts}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
