"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
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
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { OperationToast, type OperationToastKind } from "@/components/ui/OperationToast";
import type { FilesystemTopologySession, SessionCwdHistoryEvent, SessionTerminateAction } from "@/lib/dashboardTypes";
import { actionLabel, formatFromPath, formatTimestamp, isInitialSshEntry, statusLabel } from "./filesystemUtils";

type SidebarTab = "replay" | "commands" | "actions";
type TerminateCapability = "idle" | "loading" | "available" | "forbidden" | "unconfigured" | "error";

interface TerminateStatePayload {
  available?: boolean;
  authorized?: boolean;
  configured?: boolean;
  action?: SessionTerminateAction | null;
}

function terminateCapabilityFrom(document: TerminateStatePayload): TerminateCapability {
  return document.available ? "available" : !document.authorized ? "forbidden" : !document.configured ? "unconfigured" : "error";
}

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
  historyStatus: RegionStatus;
  historyCursor: string | null;
  selectedHistoryEventId: string | null;
  layout?: "card" | "sidebar";
  sessionIsLive?: boolean;
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
  sessionIsLive = false,
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
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("replay");
  const [sidebarTabDirection, setSidebarTabDirection] = useState(1);
  const [terminateCapability, setTerminateCapability] = useState<TerminateCapability>("idle");
  const [terminateCapabilitySessionId, setTerminateCapabilitySessionId] = useState<string | null>(null);
  const [terminateAction, setTerminateAction] = useState<SessionTerminateAction | null>(null);
  const [terminateDialogOpen, setTerminateDialogOpen] = useState(false);
  const [terminateProcessing, setTerminateProcessing] = useState(false);
  const [terminateError, setTerminateError] = useState<string | undefined>();
  const [operationToast, setOperationToast] = useState<{ kind: OperationToastKind; title: string; description: string } | null>(null);
  const shouldReduceMotion = useReducedMotion();

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
  const controlSessionId = selectedSession?.sessionId ?? null;
  const visibleTerminateAction = terminateAction?.sessionId === controlSessionId ? terminateAction : null;
  const visibleTerminateCapability = terminateCapabilitySessionId === controlSessionId ? terminateCapability : "loading";

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
  const sidebarTabColumn = SIDEBAR_TAB_COLUMN[sidebarTab];
  const sidebarContentDirection = shouldReduceMotion ? 0 : sidebarTabDirection;

  const handleSidebarTabChange = (nextTab: SidebarTab) => {
    if (nextTab === sidebarTab) return;
    setSidebarTabDirection(SIDEBAR_TAB_COLUMN[nextTab] > sidebarTabColumn ? 1 : -1);
    setSidebarTab(nextTab);
  };

  const fetchTerminateState = useCallback(async (sessionId: string, actionId?: string, signal?: AbortSignal) => {
    const query = actionId ? `?actionId=${encodeURIComponent(actionId)}` : "";
    const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/actions/terminate${query}`, {
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
    if (!response.ok) throw new Error("Response control status unavailable");
    return await response.json() as TerminateStatePayload;
  }, []);

  useEffect(() => {
    if (!isSidebar || sidebarTab !== "actions" || !controlSessionId) return;
    const controller = new AbortController();
    void fetchTerminateState(controlSessionId, undefined, controller.signal)
      .then((document) => {
        setTerminateAction(document.action ?? null);
        setTerminateCapability(terminateCapabilityFrom(document));
        setTerminateCapabilitySessionId(controlSessionId);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setTerminateCapability("error");
          setTerminateCapabilitySessionId(controlSessionId);
        }
      });
    return () => controller.abort();
  }, [controlSessionId, fetchTerminateState, isSidebar, sidebarTab]);

  useEffect(() => {
    if (!controlSessionId || !visibleTerminateAction || !["requested", "delivered"].includes(visibleTerminateAction.status)) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      void fetchTerminateState(controlSessionId, visibleTerminateAction.actionId, controller.signal)
        .then((document) => {
          const action = document.action ?? null;
          setTerminateAction(action);
          setTerminateCapability(terminateCapabilityFrom(document));
          setTerminateCapabilitySessionId(controlSessionId);
          if (action?.status === "verified") {
            window.clearInterval(timer);
            setOperationToast({ kind: "success", title: "Session disconnected", description: "Cowrie emitted the verified session-closed lifecycle event." });
          } else if (action?.status === "failed") {
            window.clearInterval(timer);
          }
        })
        .catch(() => undefined);
    }, 1_000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [controlSessionId, fetchTerminateState, visibleTerminateAction]);

  const handleTerminateSession = useCallback(async () => {
    if (!selectedSession) return;
    setTerminateProcessing(true);
    setTerminateError(undefined);
    try {
      const response = await fetch(`/api/sessions/${encodeURIComponent(selectedSession.sessionId)}/actions/terminate`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmation: selectedSession.sessionId }),
      });
      const document = await response.json() as { error?: string; action?: SessionTerminateAction; reconciling?: boolean };
      if (document.action) setTerminateAction(document.action);
      if (!response.ok) throw new Error(document.error ?? "Terminate request failed");
      setTerminateDialogOpen(false);
      setOperationToast(document.reconciling
        ? { kind: "success", title: "Reconciling session state", description: "The Pi no longer has this transport. Waiting for Cowrie's closure event before confirming the result." }
        : { kind: "success", title: "Disconnect requested", description: "The Pi accepted the scoped request. Waiting for Cowrie to confirm session closure." });
    } catch (error) {
      setTerminateError(error instanceof Error ? error.message : "Terminate request failed");
    } finally {
      setTerminateProcessing(false);
    }
  }, [selectedSession]);

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
                <span>Hop {selectedHistoryIndex + 1} of {displayedHistory.length}</span>
                <span>{formatTimestamp(selectedHistoryEvent?.at ?? null)}</span>
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
                /* Tab 1: Sleek Compact Route Replay */
                <>
            {/* Sleek Compact Hop Deck */}
            <div className="rounded-xl border border-border bg-surface-subtle p-2.5 shadow-2xs" aria-live="polite">
              {/* Controls & Scrubber Row */}
              <div className="flex items-center justify-between gap-1.5">
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    className="ui-button h-9 w-9 p-0 shrink-0"
                    title="Jump to first hop"
                    aria-label="First hop"
                    disabled={selectedHistoryIndex <= 0}
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
                    disabled={selectedHistoryIndex <= 0}
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
                    className={`ui-button h-9 min-h-9 px-2.5 text-xs flex items-center gap-1 shrink-0 ${
                      isPlaying ? "border-primary bg-primary text-surface" : ""
                    }`}
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
                    disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= displayedHistory.length - 1}
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
                    disabled={selectedHistoryIndex === displayedHistory.length - 1}
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

                  <span className="rounded-full bg-surface px-2 py-0.5 font-mono text-xs font-semibold text-primary border border-primary-border shrink-0">
                    Hop {selectedHistoryIndex + 1}/{displayedHistory.length}
                  </span>
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

                {/* Progress bar */}
                <div className="mt-1.5 h-1 w-full rounded-full bg-border/40 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-200 ${
                      isFailedHop ? "bg-warning" : "bg-primary"
                    }`}
                    style={{
                      width: `${
                        displayedHistory.length > 0
                          ? Math.min(100, Math.max(0, ((selectedHistoryIndex + 1) / displayedHistory.length) * 100))
                          : 0
                      }%`,
                    }}
                  />
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
                    <li key={event.id} className="relative pb-2.5 last:pb-0">
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
                              {String(index + 1).padStart(2, "0")}
                            </span>
                            {actionLabel(event)}
                          </p>
                          <time className="shrink-0 font-mono text-xs text-text-subtle whitespace-nowrap ml-1">
                            {formatTimestamp(event.at)}
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
                          className="mt-1.5 flex items-center gap-1.5 text-xs text-text-subtle"
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
            </motion.div>
          </AnimatePresence>
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
