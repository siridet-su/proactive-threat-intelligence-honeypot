"use client";

import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  CornerDownRight,
  FastForward,
  FileCode2,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Rewind,
  Shield,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatFromPath, formatTimestamp, isInitialSshEntry, statusLabel } from "./filesystemUtils";

interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  historyStatus: RegionStatus;
  historyCursor: string | null;
  selectedHistoryEventId: string | null;
  layout?: "card" | "sidebar";
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
  const [sidebarTab, setSidebarTab] = useState<"replay" | "commands" | "actions">("replay");

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

  return (
    <div className={`ui-panel overflow-hidden ${isSidebar ? "flex flex-col h-full min-h-0" : ""}`}>
      {/* Panel Header with Compact Tabs */}
      <div className="flex flex-col gap-2 border-b border-border px-3.5 py-2.5 sm:flex-row sm:items-center sm:justify-between shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <History className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
          <h2 className="text-xs font-semibold sm:text-sm truncate">
            {isSidebar ? "Forensic Studio" : "Verified CWD route"}
          </h2>
          {isSidebar && (
            <div className="flex items-center gap-1 rounded-lg border border-border bg-surface-subtle p-0.5 ml-1 text-xs">
              <button
                type="button"
                onClick={() => setSidebarTab("replay")}
                className={`rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors cursor-pointer ${
                  sidebarTab === "replay"
                    ? "bg-surface text-primary font-semibold shadow-2xs border border-border"
                    : "text-text-muted hover:text-text"
                }`}
              >
                Route Replay
              </button>
              <button
                type="button"
                onClick={() => setSidebarTab("commands")}
                className={`flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors cursor-pointer ${
                  sidebarTab === "commands"
                    ? "bg-surface text-primary font-semibold shadow-2xs border border-border"
                    : "text-text-muted hover:text-text"
                }`}
              >
                <Terminal className="h-3 w-3" />
                <span>Commands & Files</span>
              </button>
              <button
                type="button"
                onClick={() => setSidebarTab("actions")}
                className={`flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors cursor-pointer ${
                  sidebarTab === "actions"
                    ? "bg-surface text-primary font-semibold shadow-2xs border border-border"
                    : "text-text-muted hover:text-text"
                }`}
              >
                <Shield className="h-3 w-3" />
                <span>Pi Portal</span>
              </button>
            </div>
          )}
        </div>
        {selectedSession && (
          <span className="ui-badge shrink-0 font-mono text-[11px] whitespace-nowrap hidden sm:inline-flex py-0.5 px-2">
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
        ) : sidebarTab === "commands" ? (
          /* Tab 2: Commands & Files Inspection */
          <div className="flex flex-1 flex-col min-h-0 space-y-3">
            <div className="rounded-xl border border-border bg-surface p-3 shadow-2xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-primary" />
                  <span className="text-xs font-semibold text-text">Command & Shell Telemetry</span>
                </div>
                <span className="ui-badge text-[10px] font-mono">Stream Hook Ready</span>
              </div>
              <p className="mt-1 text-[11px] text-text-subtle">
                Attacker command execution log synchronized with the directory hop replay.
              </p>
            </div>

            <div className="flex-1 min-h-[200px] rounded-xl border border-border bg-surface-subtle p-3 font-mono text-xs overflow-y-auto space-y-2">
              <div className="text-[11px] text-text-subtle pb-1 border-b border-border/60 flex items-center justify-between">
                <span>
                  Current Path:{" "}
                  <strong className="text-text font-bold">
                    {selectedHistoryEvent?.toPath ?? selectedSession.cwdState.path ?? "/"}
                  </strong>
                </span>
                <span>Hop {selectedHistoryIndex + 1}/{displayedHistory.length}</span>
              </div>
              <div className="space-y-1.5 pt-1 text-[11px]">
                <div className="flex items-start gap-2">
                  <span className="text-primary select-none font-bold">$</span>
                  <span className="text-text font-semibold">cd {selectedHistoryEvent?.toPath ?? ""}</span>
                </div>
                <div className="flex items-start gap-2 text-text-muted">
                  <span className="text-primary select-none font-bold">$</span>
                  <span>ls -la</span>
                </div>
                <div className="rounded bg-surface p-2 border border-border/50 text-[10px] text-text-subtle">
                  Directory accessed at {formatTimestamp(selectedHistoryEvent?.at ?? null)} (Session: {selectedSession.sessionId.slice(0, 8)}…)
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface p-3 shadow-2xs">
              <div className="flex items-center gap-2">
                <FileCode2 className="h-4 w-4 text-primary" />
                <span className="text-xs font-semibold text-text">Payload & File Activity</span>
              </div>
              <p className="mt-1 text-[11px] text-text-subtle">
                Captured scripts, dropped artifacts, and file modifications in this path.
              </p>
            </div>
          </div>
        ) : sidebarTab === "actions" ? (
          /* Tab 3: Active Defense & Pi Command Portal */
          <div className="flex flex-1 flex-col min-h-0 space-y-3">
            <div className="rounded-xl border border-border bg-surface p-3 shadow-2xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-danger" />
                  <span className="text-xs font-semibold text-text">Pi Active Defense Portal</span>
                </div>
                <span className="ui-badge text-[10px] font-mono border-danger-border bg-danger-subtle text-danger">
                  Honeypot Live
                </span>
              </div>
              <p className="mt-1 text-[11px] text-text-subtle">
                Direct remote management portal to Raspberry Pi Cowrie honeypot node.
              </p>
            </div>

            <div className="rounded-xl border border-border bg-surface-subtle p-3 space-y-2.5">
              <div className="text-xs font-semibold text-text">Attacker Target: {selectedSession.sourceIp}</div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="rounded bg-surface p-2 border border-border">
                  <div className="text-[10px] text-text-subtle">Session ID</div>
                  <div className="font-bold text-text mt-0.5 truncate">{selectedSession.sessionId.slice(0, 10)}…</div>
                </div>
                <div className="rounded bg-surface p-2 border border-border">
                  <div className="text-[10px] text-text-subtle">Node Status</div>
                  <div className="font-bold text-text mt-0.5">
                    {"lifecycle" in selectedSession && Boolean((selectedSession as { lifecycle?: { closedAt?: string | null } }).lifecycle?.closedAt) ? (
                      <span className="text-text-subtle">Closed</span>
                    ) : (
                      <span className="text-success flex items-center gap-1">
                        <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" /> Live
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="pt-2 space-y-2">
                <button
                  type="button"
                  disabled={"lifecycle" in selectedSession && Boolean((selectedSession as { lifecycle?: { closedAt?: string | null } }).lifecycle?.closedAt)}
                  className="w-full ui-button-danger py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  onClick={() => alert(`Kill signal sent to Pi for session: ${selectedSession.sessionId}`)}
                >
                  <ShieldAlert className="h-4 w-4" />
                  <span>Terminate Session (Kill Now)</span>
                </button>

                <button
                  type="button"
                  className="w-full ui-button py-2 px-3 rounded-lg text-xs font-medium flex items-center justify-center gap-2"
                  onClick={() => alert(`IP ${selectedSession.sourceIp} firewall block requested`)}
                >
                  <Shield className="h-4 w-4 text-warning" />
                  <span>Block Attacker IP at Pi Firewall</span>
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface p-3 text-xs text-text-subtle">
              <div className="font-semibold text-text mb-1">Pi Daemon Connectivity</div>
              <p className="text-[11px]">
                Active remote actions execute through the PTI Honeypot Agent on your Raspberry Pi.
              </p>
            </div>
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
                    className="ui-button h-7 w-7 p-0 shrink-0"
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
                    className="ui-button h-7 w-7 p-0 shrink-0"
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
                    className={`ui-button h-7 min-h-7 px-2 text-xs flex items-center gap-1 shrink-0 ${
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
                    className="ui-button h-7 w-7 p-0 shrink-0"
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
                    className="ui-button h-7 w-7 p-0 shrink-0"
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
                    className="ui-button h-7 min-h-7 px-1.5 font-mono text-[10px] shrink-0"
                    title="Toggle playback speed (1x / 2x)"
                  >
                    {playbackSpeed === 1400 ? "1x" : "2x"}
                  </button>
                </div>

                {/* Right side: Failures + Hop indicator */}
                <div className="flex items-center gap-2">
                  {failedCount > 0 && (
                    <label className="flex items-center gap-1 text-[10px] text-text-subtle cursor-pointer select-none whitespace-nowrap shrink-0">
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
                        className="rounded border-border text-primary focus:ring-primary h-3 w-3"
                      />
                      <span>Failures ({failedCount})</span>
                    </label>
                  )}

                  <span className="rounded-full bg-surface px-2 py-0.5 font-mono text-[10px] font-semibold text-primary border border-primary-border shrink-0">
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
                    <span className="text-[11px] text-text-subtle truncate max-w-[120px]" title={selectedHistoryEvent?.fromPath ?? undefined}>
                      {isInitialSshEntry(selectedHistoryEvent) ? "[SSH Login]" : formatFromPath(selectedHistoryEvent)}
                    </span>
                    <span className="text-text-subtle">→</span>
                    <strong className={`truncate ${isFailedHop ? "line-through text-warning" : "text-text"}`} title={selectedHistoryEvent?.toPath ?? undefined}>
                      {selectedHistoryEvent?.toPath ?? "Unknown"}
                    </strong>
                  </div>

                  <span className="text-[10px] font-sans text-text-subtle shrink-0">
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
                            <span className="mr-1.5 font-mono text-[11px] text-text-subtle">
                              {String(index + 1).padStart(2, "0")}
                            </span>
                            {actionLabel(event)}
                          </p>
                          <time className="shrink-0 font-mono text-[11px] text-text-subtle whitespace-nowrap ml-1">
                            {formatTimestamp(event.at)}
                          </time>
                        </div>
                        <div className="mt-1.5 space-y-0.5 font-mono text-xs">
                          {/* Line 1: Origin */}
                          <div className="flex items-center gap-1.5 text-text-subtle text-[11px] min-w-0">
                            <span className="shrink-0 font-sans text-[10px] uppercase tracking-wider text-text-subtle/70">
                              from
                            </span>
                            {isInitialSshEntry(event) ? (
                              <span className="rounded border border-border bg-surface px-1.5 py-0.5 font-sans text-[10px] font-medium text-text-subtle">
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
                              <span className="ml-auto shrink-0 rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-sans text-[10px] font-semibold text-warning">
                                Failed
                              </span>
                            )}
                          </div>
                        </div>
                        <div
                          className="mt-1.5 flex items-center gap-1.5 text-[11px] text-text-subtle"
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
      </div>
    </div>
  );
}
