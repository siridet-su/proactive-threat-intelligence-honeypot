// @refresh reset
"use client";

import { ChevronLeft, Radio, RefreshCw, Route } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type {
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";
import { CwdRouteHistory } from "./CwdRouteHistory";
import { FilesystemInspector } from "./FilesystemInspector";
import {
  buildAuditSnapshot,
  isHistoryPage,
  isSnapshot,
  type ActiveHopRoute,
  type StreamState,
} from "./filesystemUtils";
import { SessionSourceList } from "./SessionSourceList";
import { TopologyCanvas } from "./TopologyCanvas";

export function FilesystemActivity() {
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

  const historyRequest = useRef<{ generation: number; sessionId: string; controller: AbortController } | null>(null);
  const latestSnapshotAt = useRef(0);
  const selectedSessionIdRef = useRef<string | null>(null);
  const selectedLiveCwdRef = useRef<string | null>(null);

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
      }
    }, 0);
    return () => clearTimeout(timer);
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
      const session = sessionById.get(sessionId);
      historyRequest.current?.controller.abort();
      setHistory([]);
      setHistoryCursor(null);
      setSelectedHistoryEventId(null);
      selectedSessionIdRef.current = sessionId;
      setSelectedSessionId(sessionId);
      if (session?.cwdState.path) {
        selectedLiveCwdRef.current = session.cwdState.path;
        setSelectedPath(snapshot?.nodes.some((n) => n.path === session.cwdState.path) ? session.cwdState.path : null);
      }
    },
    [sessionById, snapshot?.nodes],
  );

  // Decoupled directory selection: inspects directory metadata without destroying the currently audited session
  const selectPath = (path: string | null) => {
    setSelectedPath(path);
  };

  const switchViewMode = useCallback(
    (mode: "live" | "audit", targetSessionId?: string) => {
      setViewMode(mode);
      const sid = targetSessionId ?? selectedSessionIdRef.current;
      if (targetSessionId) {
        selectSession(targetSessionId);
      }
      if (typeof window !== "undefined") {
        const url = new URL(window.location.href);
        if (mode === "audit") {
          url.searchParams.set("view", "audit");
          if (sid) url.searchParams.set("sessionId", sid);
        } else {
          url.searchParams.delete("view");
          url.searchParams.delete("sessionId");
        }
        window.history.replaceState(null, "", url.toString());
      }
    },
    [selectSession],
  );

  const auditSnapshot = useMemo(() => {
    if (viewMode !== "audit") return null;
    return buildAuditSnapshot(snapshot, selectedSession, history);
  }, [viewMode, snapshot, selectedSession, history]);

  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);

  const selectedHistoryIndex = useMemo(() => {
    if (!chronologicalHistory.length) return -1;
    const index = chronologicalHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : chronologicalHistory.length - 1;
  }, [chronologicalHistory, selectedHistoryEventId]);

  const activeHop: ActiveHopRoute | null = useMemo(() => {
    if (selectedHistoryIndex < 0 || !chronologicalHistory[selectedHistoryIndex]) return null;
    const currentEvent = chronologicalHistory[selectedHistoryIndex];
    const isFailed = currentEvent.action === "failed_change";
    const visitedStepMap: Record<string, number> = {};
    for (let i = 0; i <= selectedHistoryIndex; i++) {
      const ev = chronologicalHistory[i];
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
      totalSteps: chronologicalHistory.length,
      visitedPaths: Object.keys(visitedStepMap),
      visitedStepMap,
      isFailedAttempt: isFailed,
    };
  }, [chronologicalHistory, selectedHistoryIndex]);

  return (
    <div className="space-y-5">
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
            role="tablist"
            aria-label="Filesystem views"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === "live"}
              onClick={() => switchViewMode("live")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
                viewMode === "live"
                  ? "bg-surface text-primary shadow-xs border border-border"
                  : "text-text-muted hover:text-text"
              }`}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              Live Topology
              {snapshot?.sessions.length ? (
                <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-[10px] font-mono text-text-subtle border border-border">
                  {snapshot.sessions.length}
                </span>
              ) : null}
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={viewMode === "audit"}
              onClick={() => switchViewMode("audit")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
                viewMode === "audit"
                  ? "bg-surface text-primary shadow-xs border border-border"
                  : "text-text-muted hover:text-text"
              }`}
            >
              <Route className="h-3.5 w-3.5" aria-hidden="true" />
              Session Audit & Replay
              {selectedSession && (
                <span className="rounded-full bg-surface-subtle px-1.5 py-0.2 text-[10px] font-mono text-text-subtle border border-border">
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

          <aside className="min-w-0 space-y-4" aria-live="polite">
            <FilesystemInspector
              selectedSession={selectedSession}
              selectedClosedSession={selectedClosedSession}
              selectedNode={selectedNode}
              sessions={snapshot?.sessions ?? []}
              liveSessionCount={selectedNodeLiveSessionCount}
              selectedSessionId={selectedSessionId}
              onSelectSession={selectSession}
              onSelectPath={selectPath}
              onOpenAudit={(sessionId) => switchViewMode("audit", sessionId)}
            />
            <SessionSourceList
              sessions={snapshot?.sessions ?? []}
              recentClosedSessions={snapshot?.recentClosedSessions ?? []}
              selectedSessionId={selectedSessionId}
              onSelectSession={selectSession}
              onAuditSession={(sessionId) => switchViewMode("audit", sessionId)}
            />
          </aside>
        </div>
      ) : (
        /* Mode 2: Session Forensics & Replay Mode (Side-by-Side 100% Viewport) */
        <div className="space-y-4">
          {/* Target Session Selector Bar */}
          <div className="flex flex-col gap-3 rounded-xl border border-border bg-surface px-4 py-3 sm:flex-row sm:items-center sm:justify-between shadow-xs">
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => switchViewMode("live")}
                className="ui-button h-8 px-2.5 text-xs flex items-center gap-1.5"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Back to Live Topology
              </button>
              <div className="h-4 w-px bg-border hidden sm:block" />
              <span className="text-xs text-text-subtle font-medium">Audited Session:</span>
              <select
                value={selectedSessionId ?? ""}
                onChange={(e) => {
                  const nextId = e.target.value;
                  if (nextId) selectSession(nextId);
                }}
                className="rounded-lg border border-border bg-surface-subtle px-2.5 py-1 font-mono text-xs text-text focus:border-primary focus:outline-none"
              >
                {snapshot?.sessions.length ? (
                  <optgroup label="Active Sessions">
                    {snapshot.sessions.map((s) => (
                      <option key={s.sessionId} value={s.sessionId}>
                        {s.sourceIp} · {s.sessionId.slice(0, 8)}… ({s.cwdState.path})
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {snapshot?.recentClosedSessions.length ? (
                  <optgroup label="Closed Sessions">
                    {snapshot.recentClosedSessions.map((s) => (
                      <option key={s.sessionId} value={s.sessionId}>
                        {s.sourceIp} · {s.sessionId.slice(0, 8)}… (Closed)
                      </option>
                    ))}
                  </optgroup>
                ) : null}
              </select>
            </div>

            <div className="flex items-center gap-2 text-xs">
              {selectedSession && (
                <span className="font-mono text-xs text-text-subtle hidden md:inline">
                  IP: <strong className="text-text">{selectedSession.sourceIp}</strong>
                </span>
              )}
              <span className="ui-badge border-primary-border bg-primary-subtle text-primary text-xs font-semibold">
                Forensic Playback Synchronized
              </span>
            </div>
          </div>

          {/* Side-by-Side Audit Layout */}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] lg:items-stretch">
            <div className="min-w-0">
              <TopologyCanvas
                snapshot={auditSnapshot ?? snapshot}
                regionStatus={regionStatus}
                streamState={streamState}
                selectedSessionId={selectedSessionId}
                selectedPath={selectedPath}
                activeHop={activeHop}
                title={`Attack Trajectory: ${selectedSession?.sourceIp ?? "Session"}`}
                subtitle="All historical directories touched by this session are preserved on the canvas."
                onSelectSession={selectSession}
                onSelectPath={selectPath}
              />
            </div>

            <div className="min-w-0">
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
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
