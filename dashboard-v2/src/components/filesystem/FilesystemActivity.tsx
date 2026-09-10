// @refresh reset
"use client";

import { Radio, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type {
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";
import { CwdRouteHistory } from "./CwdRouteHistory";
import { FilesystemInspector } from "./FilesystemInspector";
import { isHistoryPage, isSnapshot, type StreamState } from "./filesystemUtils";
import { SessionSourceList } from "./SessionSourceList";
import { TopologyCanvas } from "./TopologyCanvas";

export function FilesystemActivity() {
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
  const loadHistory = useCallback(async (sessionId: string, cursor: string | null, append = false) => {
    const generation = (historyRequest.current?.generation ?? 0) + 1;
    historyRequest.current?.controller.abort();
    const controller = new AbortController();
    historyRequest.current = { generation, sessionId, controller };
    if (!append) {
      setHistory([]);
      setHistoryCursor(null);
      setSelectedHistoryEventId(null);
    }
    setHistoryStatus(append ? "refreshing" : "loading");
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

  const selectSession = (sessionId: string) => {
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
  };

  const selectPath = (path: string | null) => {
    const sessionId = path
      ? [...(snapshot?.sessions ?? [])]
          .filter((session) => session.cwdState.path === path)
          .sort((left, right) => {
            const leftObservedAt = Date.parse(left.cwdState.observedAt ?? "") || 0;
            const rightObservedAt = Date.parse(right.cwdState.observedAt ?? "") || 0;
            return rightObservedAt - leftObservedAt;
          })[0]?.sessionId
      : undefined;

    if (sessionId) {
      selectSession(sessionId);
      return;
    }

    historyRequest.current?.controller.abort();
    setHistory([]);
    setHistoryCursor(null);
    setSelectedHistoryEventId(null);
    selectedSessionIdRef.current = null;
    setSelectedSessionId(null);
    selectedLiveCwdRef.current = null;
    setSelectedPath(path);
  };

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-text">Filesystem activity</h1>
          <p className="mt-0.5 max-w-2xl text-xs text-text-muted">
            Inspect observed Cowrie working-directory topology and audit recorded path changes.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
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
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem] xl:items-start">
        <div className="min-w-0 space-y-6">
          <TopologyCanvas
            snapshot={snapshot}
            regionStatus={regionStatus}
            streamState={streamState}
            selectedSessionId={selectedSessionId}
            selectedPath={selectedPath}
            onSelectSession={selectSession}
            onSelectPath={selectPath}
          />

          <CwdRouteHistory
            selectedSession={selectedSession}
            history={history}
            historyStatus={historyStatus}
            historyCursor={historyCursor}
            selectedHistoryEventId={selectedHistoryEventId}
            onSelectHistoryEventId={setSelectedHistoryEventId}
            onLoadEarlier={() => {
              if (selectedSessionId) void loadHistory(selectedSessionId, historyCursor, true);
            }}
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
          />
          <SessionSourceList
            sessions={snapshot?.sessions ?? []}
            recentClosedSessions={snapshot?.recentClosedSessions ?? []}
            selectedSessionId={selectedSessionId}
            onSelectSession={selectSession}
          />
        </aside>
      </div>
    </div>
  );
}
