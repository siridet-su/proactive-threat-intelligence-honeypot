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
import { isHistoryPage, isSnapshot, type StreamState } from "./filesystemUtils";
import { PathInspector } from "./PathInspector";
import { RecentClosedSessions } from "./RecentClosedSessions";
import { SessionContextCard } from "./SessionContextCard";
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
  const initializedSelection = useRef(false);

  const applySnapshot = useCallback((data: FilesystemTopologySnapshot) => {
    const timestamp = Date.parse(data.generatedAt);
    if (Number.isFinite(timestamp) && timestamp < latestSnapshotAt.current) return;
    if (Number.isFinite(timestamp)) latestSnapshotAt.current = timestamp;
    const selectingInitialSession = !initializedSelection.current && Boolean(data.sessions[0]);
    if (selectingInitialSession) initializedSelection.current = true;
    setSnapshot(data);
    setRegionStatus("ready");
    setSelectedSessionId((current) => {
      if (current) {
        return [...data.sessions, ...data.recentClosedSessions].some((session) => session.sessionId === current)
          ? current
          : null;
      }
      if (selectingInitialSession) return data.sessions[0].sessionId;
      return null;
    });
    setSelectedPath((current) => {
      if (current) return data.nodes.some((node) => node.path === current) ? current : null;
      return selectingInitialSession ? data.nodes[0]?.path ?? null : null;
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
    setSelectedSessionId(sessionId);
    if (session?.cwdState.path) {
      setSelectedPath(snapshot?.nodes.some((n) => n.path === session.cwdState.path) ? session.cwdState.path : null);
    }
  };

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-4 border-b border-border pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-primary">Runtime filesystem</p>
          <h1 className="text-2xl font-semibold tracking-tight text-text">Filesystem activity</h1>
          <p className="mt-2 max-w-2xl text-sm text-text-muted">
            Inspect the observed Cowrie working-directory topology, then audit a selected session&apos;s recorded path
            changes.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
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

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <TopologyCanvas
          snapshot={snapshot}
          regionStatus={regionStatus}
          streamState={streamState}
          selectedSessionId={selectedSessionId}
          selectedPath={selectedPath}
          onSelectSession={selectSession}
          onSelectPath={(path) => setSelectedPath(path)}
        />

        <aside className="space-y-4" aria-live="polite">
          <PathInspector
            key={selectedNode?.path ?? "no-selected-path"}
            selectedNode={selectedNode}
            sessionById={sessionById}
            selectedSessionId={selectedSessionId}
            onSelectSession={selectSession}
          />
          <RecentClosedSessions
            recentClosedSessions={snapshot?.recentClosedSessions ?? []}
            selectedSessionId={selectedSessionId}
            onSelectSession={selectSession}
          />
        </aside>
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
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
        <SessionContextCard
          selectedSession={selectedSession}
          selectedClosedSession={selectedClosedSession}
        />
      </section>
    </div>
  );
}
