"use client";

import { motion, useReducedMotion } from "framer-motion";
import { ChevronLeft, ChevronRight, CircleDot, Crosshair, Grip, History, MousePointer2, Plus, Radio, RefreshCw, Route, Search, ShieldAlert, Terminal, ZoomIn, ZoomOut } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologyNode, FilesystemTopologySession, FilesystemTopologySnapshot, SessionCwdHistoryEvent, SessionCwdHistoryPage } from "@/lib/dashboardTypes";

type StreamState = "connecting" | "live" | "stale";
type Pan = { x: number; y: number };

function isSnapshot(value: unknown): value is FilesystemTopologySnapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<FilesystemTopologySnapshot>;
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.sessions) &&
    typeof candidate.truncated === "boolean" && typeof candidate.generatedAt === "string";
}

function isHistoryPage(value: unknown): value is SessionCwdHistoryPage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SessionCwdHistoryPage>;
  return Array.isArray(candidate.items) && (typeof candidate.nextCursor === "string" || candidate.nextCursor === null);
}

function formatTimestamp(value: string | null) {
  if (!value) return "No timestamp";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No timestamp";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function statusLabel(status: FilesystemTopologySession["cwdState"]["status"]) {
  if (status === "confirmed") return "Confirmed";
  if (status === "observed") return "Observed";
  if (status === "conditional_candidate") return "Conditional";
  return "Unknown";
}

function actionLabel(event: SessionCwdHistoryEvent) {
  if (event.action === "entered") return "Entered directory";
  if (event.action === "failed_change") return "Directory change failed";
  return "Changed directory";
}

const INSPECTOR_PAGE_SIZE = 12;
const GRAPH_CALLOUT_LIMIT = 18;
const GRAPH_NODE_LIMIT = 42;

type GraphNode = FilesystemTopologyNode & { x: number; y: number };

function pointForGraph(nodes: FilesystemTopologyNode[], sessions: FilesystemTopologySession[], selectedPath: string | null): GraphNode[] {
  const byPath = new Map(nodes.map((node) => [node.path, node]));
  const included = new Set<string>(["/"]);
  const recentSessions = [...sessions].sort((left, right) => {
    return Date.parse(right.cwdState.observedAt ?? "") - Date.parse(left.cwdState.observedAt ?? "");
  }).slice(0, GRAPH_CALLOUT_LIMIT);
  const includePath = (path: string | null) => {
    let current = path;
    while (current) {
      included.add(current);
      current = byPath.get(current)?.parentPath ?? null;
    }
  };
  for (const session of recentSessions) includePath(session.cwdState.path);
  includePath(selectedPath);
  for (const node of [...nodes].sort((left, right) => Date.parse(right.observedAt ?? "") - Date.parse(left.observedAt ?? ""))) {
    if (included.size >= GRAPH_NODE_LIMIT) break;
    includePath(node.path);
  }

  const selected = nodes.filter((node) => included.has(node.path));
  const maxDepth = Math.max(1, ...selected.map((node) => node.depth));
  const levels = new Map<number, FilesystemTopologyNode[]>();
  for (const node of selected) {
    const group = levels.get(node.depth) ?? [];
    group.push(node);
    levels.set(node.depth, group);
  }
  return selected.map((node) => {
    const level = [...(levels.get(node.depth) ?? [])].sort((left, right) => left.path.localeCompare(right.path));
    const index = level.findIndex((item) => item.path === node.path);
    const x = level.length === 1 ? 50 : 9 + (82 * index) / (level.length - 1);
    const y = 13 + (72 * node.depth) / maxDepth;
    return { ...node, x, y };
  });
}

export function FilesystemActivity() {
  const reducedMotion = useReducedMotion();
  const [snapshot, setSnapshot] = useState<FilesystemTopologySnapshot | null>(null);
  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [history, setHistory] = useState<SessionCwdHistoryEvent[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyStatus, setHistoryStatus] = useState<RegionStatus>("loading");
  const [pan, setPan] = useState<Pan>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [pathSessionQuery, setPathSessionQuery] = useState("");
  const [pathSessionPage, setPathSessionPage] = useState(0);
  // The initial live connection enables manual refresh after hydration.
  const [isHydrated, setIsHydrated] = useState(false);
  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);
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
      if (current) return data.sessions.some((session) => session.sessionId === current) ? current : null;
      if (selectingInitialSession) return data.sessions[0].sessionId;
      return null;
    });
    setSelectedPath((current) => {
      if (current) return data.nodes.some((node) => node.path === current) ? current : null;
      return selectingInitialSession ? data.nodes[0]?.path ?? null : null;
    });
  }, []);

  const refresh = useCallback(async () => {
    setRegionStatus((current) => snapshot ? "refreshing" : current === "error" ? "loading" : current);
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
        if (!disposed) setRegionStatus((current) => current === "ready" ? "stale" : "error");
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
    const onMessage = (event: MessageEvent<string>) => {
      try {
        const message: unknown = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
        const data = (message as { data?: unknown }).data;
        if (!isSnapshot(data)) return;
        applySnapshot(data);
        setStreamState("live");
      } catch { /* retain the last valid topology */ }
    };
    connect();
    return () => {
      disposed = true;
      source?.close();
      if (retry !== null) window.clearTimeout(retry);
    };
  }, [applySnapshot]);

  const loadHistory = useCallback(async (sessionId: string, cursor: string | null, append = false) => {
    const generation = (historyRequest.current?.generation ?? 0) + 1;
    historyRequest.current?.controller.abort();
    const controller = new AbortController();
    historyRequest.current = { generation, sessionId, controller };
    if (!append) {
      setHistory([]);
      setHistoryCursor(null);
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
      setHistory((current) => append ? [...current, ...data.items] : data.items);
      setHistoryCursor(data.nextCursor);
      setHistoryStatus("ready");
    } catch {
      if (controller.signal.aborted || historyRequest.current?.generation !== generation) return;
      setHistoryStatus("error");
    }
  }, []);

  useEffect(() => {
    if (!selectedSessionId) {
      historyRequest.current?.controller.abort();
      return;
    }
    const request = window.setTimeout(() => { void loadHistory(selectedSessionId, null); }, 0);
    return () => {
      window.clearTimeout(request);
      if (historyRequest.current?.sessionId === selectedSessionId) historyRequest.current.controller.abort();
    };
  }, [loadHistory, selectedSessionId]);

  const selectedSession = useMemo(() => snapshot?.sessions.find((session) => session.sessionId === selectedSessionId) ?? null, [selectedSessionId, snapshot]);
  const selectedNode = useMemo(() => snapshot?.nodes.find((node) => node.path === selectedPath) ?? null, [selectedPath, snapshot]);
  const sessionById = useMemo(() => new Map(snapshot?.sessions.map((session) => [session.sessionId, session])), [snapshot]);
  const graphNodes = useMemo(
    () => pointForGraph(snapshot?.nodes ?? [], snapshot?.sessions ?? [], selectedPath),
    [selectedPath, snapshot?.nodes, snapshot?.sessions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const graphSessions = useMemo(() => [...(snapshot?.sessions ?? [])]
    .sort((left, right) => Date.parse(right.cwdState.observedAt ?? "") - Date.parse(left.cwdState.observedAt ?? ""))
    .filter((session) => session.cwdState.path && graphNodeByPath.has(session.cwdState.path))
    .slice(0, GRAPH_CALLOUT_LIMIT), [graphNodeByPath, snapshot?.sessions]);

  const matchingPathSessionIds = useMemo(() => {
    const query = pathSessionQuery.trim().toLowerCase();
    const sessionIds = selectedNode?.sessionIds ?? [];
    if (!query) return sessionIds;
    return sessionIds.filter((id) => {
      const session = sessionById.get(id);
      return id.toLowerCase().includes(query) || session?.sourceIp.toLowerCase().includes(query);
    });
  }, [pathSessionQuery, selectedNode?.sessionIds, sessionById]);
  const pathSessionPageCount = Math.max(1, Math.ceil(matchingPathSessionIds.length / INSPECTOR_PAGE_SIZE));
  const safePathSessionPage = Math.min(pathSessionPage, pathSessionPageCount - 1);
  const visiblePathSessionIds = matchingPathSessionIds.slice(
    safePathSessionPage * INSPECTOR_PAGE_SIZE,
    (safePathSessionPage + 1) * INSPECTOR_PAGE_SIZE,
  );

  const selectSession = (sessionId: string) => {
    const session = sessionById.get(sessionId);
    historyRequest.current?.controller.abort();
    setHistory([]);
    setHistoryCursor(null);
    setSelectedSessionId(sessionId);
    if (session?.cwdState.path) {
      setPathSessionQuery("");
      setPathSessionPage(0);
      setSelectedPath(session.cwdState.path);
    }
  };

  const resetViewport = () => { setPan({ x: 0, y: 0 }); setZoom(1); };
  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStart.current = { x: event.clientX, y: event.clientY, pan };
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (!dragStart.current) return;
    setPan({ x: dragStart.current.pan.x + event.clientX - dragStart.current.x, y: dragStart.current.pan.y + event.clientY - dragStart.current.y });
  };
  const onPointerEnd = (event: PointerEvent<HTMLDivElement>) => {
    dragStart.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };

  return <div className="space-y-6">
    <section className="flex flex-col gap-4 border-b border-border pb-6 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-primary">Runtime filesystem</p>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Filesystem activity</h1>
        <p className="mt-2 max-w-2xl text-sm text-text-muted">Inspect the observed Cowrie working-directory topology, then audit a selected session&apos;s recorded path changes.</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <span className={`ui-badge ${streamState === "live" ? "border-success-border bg-success-subtle text-success" : "border-warning-border bg-warning-subtle text-warning"}`}><Radio className="h-3.5 w-3.5" aria-hidden="true" />{streamState === "live" ? "Live updates" : streamState === "connecting" ? "Connecting" : "Reconnecting"}</span>
        <button type="button" className="ui-button" onClick={() => {
          if (!isHydrated || regionStatus === "loading" || regionStatus === "refreshing") return;
          void refresh();
        }}><RefreshCw className="h-4 w-4" aria-hidden="true" />Refresh</button>
      </div>
    </section>

    <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="ui-panel overflow-hidden" aria-busy={regionStatus === "loading"}>
        <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2"><Route className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold text-text">Live filesystem topology</h2></div>
            <p className="mt-1 text-xs text-text-subtle">Observed paths form the topology; live session callouts identify their current verified location.</p>
          </div>
          <div className="flex items-center gap-1">
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(0.7, Number((value - 0.1).toFixed(1))))}><ZoomOut className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Reset topology view" onClick={resetViewport}><MousePointer2 className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.4, Number((value + 0.1).toFixed(1))))}><ZoomIn className="h-4 w-4" /></button>
          </div>
        </div>
        {regionStatus === "error" ? <div className="p-5"><RegionState kind="error" title="Filesystem activity unavailable" description="The topology could not be loaded. Other dashboard views remain available." /></div> : regionStatus === "loading" && !snapshot ? <div className="p-5"><RegionState kind="loading" title="Loading filesystem activity" /></div> : !snapshot?.nodes.length ? <div className="p-5"><RegionState kind="empty" title="No observed working directories yet" description="The live view will populate after verified CWD telemetry is recorded." /></div> : <>
          <div className="relative min-h-[540px] overflow-hidden bg-surface-subtle p-5 sm:p-8" onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerEnd} onPointerCancel={onPointerEnd}>
            <div className="pointer-events-none absolute inset-0 opacity-50 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px]" aria-hidden="true" />
            <div className="pointer-events-none absolute left-5 top-5 flex items-center gap-2 text-xs text-text-subtle"><Grip className="h-3.5 w-3.5" aria-hidden="true" />Drag surface to pan · Select a path or live callout</div>
            <motion.div className="relative h-[500px] origin-top-left" animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }} style={reducedMotion ? { transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` } : undefined} transition={{ type: "spring", stiffness: 260, damping: 28 }}>
              <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
                {graphNodes.map((node) => {
                  const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                  if (!parent) return null;
                  return <path key={`${parent.path}-${node.path}`} d={`M ${parent.x} ${parent.y} C ${parent.x} ${(parent.y + node.y) / 2}, ${node.x} ${(parent.y + node.y) / 2}, ${node.x} ${node.y}`} fill="none" stroke="var(--border-strong)" strokeWidth="0.35" />;
                })}
                {graphSessions.map((session, index) => {
                  const node = graphNodeByPath.get(session.cwdState.path ?? "");
                  if (!node) return null;
                  const left = index % 2 === 0;
                  const labelX = left ? 23 : 77;
                  const labelY = 15 + (Math.floor(index / 2) % 8) * 10;
                  return <g key={`leader-${session.sessionId}`}><path d={`M ${node.x} ${node.y} C ${(node.x + labelX) / 2} ${node.y}, ${(node.x + labelX) / 2} ${labelY}, ${labelX} ${labelY}`} fill="none" stroke="var(--primary)" strokeWidth="0.32" strokeDasharray="1.1 1.4" /><circle cx={node.x} cy={node.y} r="1.15" fill="var(--surface)" stroke="var(--primary)" strokeWidth="0.48" /></g>;
                })}
              </svg>
              {graphNodes.map((node) => <button key={node.path} type="button" aria-pressed={node.path === selectedPath} onClick={() => { setPathSessionQuery(""); setPathSessionPage(0); setSelectedPath(node.path); }} style={{ left: `${node.x}%`, top: `${node.y}%` }} className={`absolute z-10 flex max-w-40 -translate-x-1/2 -translate-y-1/2 items-center gap-2 rounded-lg border px-2.5 py-1.5 text-left shadow-sm transition-colors duration-150 ${node.path === selectedPath ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"}`}><Crosshair className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" /><span className="truncate font-mono text-xs">{node.path}</span><span className="rounded-full bg-info-subtle px-1.5 text-xs font-semibold text-info">{node.sessionIds.length}</span></button>)}
              {graphSessions.map((session, index) => {
                const left = index % 2 === 0;
                const top = 15 + (Math.floor(index / 2) % 8) * 10;
                return <button key={`callout-${session.sessionId}`} type="button" onClick={() => selectSession(session.sessionId)} style={{ left: left ? "1%" : undefined, right: left ? undefined : "1%", top: `${top}%` }} className={`absolute z-20 flex w-40 items-center gap-2 rounded-lg border px-2.5 py-2 text-left shadow-sm transition-colors duration-150 ${session.sessionId === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"}`}><span className={`h-2 w-2 shrink-0 rounded-full ${streamState === "live" ? "bg-success" : "bg-warning"}`} aria-hidden="true" /><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span><span className="block truncate font-mono text-[11px] text-text-subtle">{session.sessionId}</span></span></button>;
              })}
              <div className="pointer-events-none absolute bottom-2 left-1/2 -translate-x-1/2 rounded-full border border-border bg-surface px-3 py-1.5 text-xs text-text-muted shadow-sm"><span className="font-semibold text-text">{graphNodes.length}</span> paths mapped · <span className="font-semibold text-text">{graphSessions.length}</span> live callouts</div>
            </motion.div>
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-border px-5 py-3 text-xs text-text-muted"><span><strong className="text-text">{snapshot.nodes.length}</strong> observed paths</span><span><strong className="text-text">{snapshot.sessions.length}</strong> sessions with a known CWD</span><span>Snapshot {formatTimestamp(snapshot.generatedAt)}</span></div>
          {snapshot.truncated && <div className="flex gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted"><ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" /><p>Showing the latest {snapshot.sessions.length} observed sessions. Older sessions are not included in this live topology.</p></div>}
        </>}
      </div>

      <aside className="ui-panel h-fit p-5" aria-live="polite">
        <div className="flex items-center gap-2"><CircleDot className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Path inspector</h2></div>
        {selectedNode ? <>
          <p className="mt-5 break-all font-mono text-sm text-text">{selectedNode.path}</p>
          <dl className="mt-5 space-y-3 text-sm"><div className="flex justify-between gap-4"><dt className="text-text-subtle">Observed sessions</dt><dd className="font-semibold text-text">{selectedNode.sessionIds.length}</dd></div><div className="flex justify-between gap-4"><dt className="text-text-subtle">Latest observation</dt><dd className="text-right text-text-muted">{formatTimestamp(selectedNode.observedAt)}</dd></div></dl>
          <div className="mt-6 border-t border-border pt-4">
            <div className="mb-3 flex items-center justify-between gap-3"><p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Sessions at this path</p><span className="text-xs text-text-subtle">{matchingPathSessionIds.length}</span></div>
            <label className="relative block"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" aria-hidden="true" /><span className="sr-only">Filter sessions at this path</span><input type="search" value={pathSessionQuery} onChange={(event) => { setPathSessionQuery(event.target.value); setPathSessionPage(0); }} className="ui-field h-9 min-h-9 pl-9 text-xs" placeholder="Find session or source IP" /></label>
            <div className="mt-3 space-y-2">{visiblePathSessionIds.map((id) => { const session = sessionById.get(id); return <button key={id} type="button" onClick={() => selectSession(id)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors ${id === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border hover:bg-surface-hover"}`}><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{id}</span><span className="mt-0.5 block font-mono text-xs text-text-subtle">{session?.sourceIp ?? "Unknown"}</span></span><ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" /></button>; })}</div>
            {matchingPathSessionIds.length === 0 && <p className="mt-3 text-xs text-text-subtle">No sessions match this filter.</p>}
            {pathSessionPageCount > 1 && <div className="mt-3 flex items-center justify-between gap-2"><button type="button" className="ui-button h-8 min-h-8 px-2 text-xs" disabled={safePathSessionPage === 0} onClick={() => setPathSessionPage((page) => Math.max(0, page - 1))}><ChevronLeft className="h-3.5 w-3.5" />Previous</button><span className="text-xs text-text-subtle">{safePathSessionPage + 1} / {pathSessionPageCount}</span><button type="button" className="ui-button h-8 min-h-8 px-2 text-xs" disabled={safePathSessionPage >= pathSessionPageCount - 1} onClick={() => setPathSessionPage((page) => Math.min(pathSessionPageCount - 1, page + 1))}>Next<ChevronRight className="h-3.5 w-3.5" /></button></div>}
          </div>
        </> : <p className="mt-5 text-sm text-text-muted">Select a directory to inspect the sessions that were observed there.</p>}
      </aside>
    </section>

    <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="ui-panel overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><History className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Session path audit</h2></div><p className="mt-1 text-xs text-text-subtle">Append-only events for the selected session; historical records are not inferred from commands.</p></div>{selectedSession && <span className="ui-badge font-mono text-xs">{selectedSession.sessionId}</span>}</div>
        <div className="p-5">
          {!selectedSession ? <RegionState kind="empty" title="Select a session to inspect its path history" description="Choose a session from the topology or inspector." /> : historyStatus === "error" && !history.length ? <RegionState kind="error" title="Session history unavailable" description="The selected CWD history could not be loaded." /> : historyStatus === "loading" && !history.length ? <RegionState kind="loading" title="Loading session history" /> : !history.length ? <RegionState kind="empty" title="No CWD transition events recorded" description="The session has a current observed path, but no historical transition records are available yet." /> : <ol className="relative space-y-0 border-l border-border pl-6">{history.map((event) => <li key={event.id} className="relative pb-6 last:pb-0"><span className={`absolute -left-[31px] top-1 flex h-3 w-3 rounded-full border-2 border-surface ${event.action === "failed_change" ? "bg-danger" : "bg-info"}`} aria-hidden="true" /><div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between"><p className="font-medium text-text">{actionLabel(event)}</p><time className="font-mono text-xs text-text-subtle">{formatTimestamp(event.at)}</time></div><p className="mt-2 break-all font-mono text-xs text-text-muted"><span>{event.fromPath ?? "Unknown"}</span><span className="px-2 text-primary">→</span><span>{event.toPath ?? "Unknown"}</span></p><p className="mt-1 text-xs text-text-subtle">{statusLabel(event.status)}{event.sequence !== null ? ` · event ${event.sequence}` : ""}</p></li>)}</ol>}
          {historyCursor && <button type="button" className="ui-button mt-5" onClick={() => selectedSessionId && void loadHistory(selectedSessionId, historyCursor, true)} disabled={historyStatus === "refreshing"}>{historyStatus === "refreshing" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}Load earlier events</button>}
        </div>
      </div>
      <aside className="ui-panel h-fit p-5"><div className="flex items-center gap-2"><Terminal className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Session context</h2></div>{selectedSession ? <dl className="mt-5 space-y-4 text-sm"><div><dt className="text-xs text-text-subtle">Source IP</dt><dd className="mt-1 font-mono text-text">{selectedSession.sourceIp}</dd></div><div><dt className="text-xs text-text-subtle">Current observed path</dt><dd className="mt-1 break-all font-mono text-text">{selectedSession.cwdState.path ?? "Unknown"}</dd></div><div><dt className="text-xs text-text-subtle">Confidence</dt><dd className="mt-1"><span className="ui-badge border-info-border bg-info-subtle text-info">{statusLabel(selectedSession.cwdState.status)}</span></dd></div><div><dt className="text-xs text-text-subtle">Observed at</dt><dd className="mt-1 text-text-muted">{formatTimestamp(selectedSession.cwdState.observedAt)}</dd></div></dl> : <p className="mt-5 text-sm text-text-muted">No session is selected.</p>}<div className="mt-6 flex gap-2 rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text-muted"><ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" /><p>Unknown paths remain unknown. This view never fills a missing directory with a guessed Linux path.</p></div></aside>
    </section>
  </div>;
}
