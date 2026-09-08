"use client";

import { motion, useReducedMotion } from "framer-motion";
import { ChevronRight, CircleDot, Folder, FolderOpen, Grip, History, MousePointer2, Plus, Radio, RefreshCw, Route, ShieldAlert, Terminal, ZoomIn, ZoomOut } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologyNode, FilesystemTopologySession, FilesystemTopologySnapshot, SessionCwdHistoryEvent, SessionCwdHistoryPage } from "@/lib/dashboardTypes";

type StreamState = "connecting" | "live" | "stale";
type Pan = { x: number; y: number };

function isSnapshot(value: unknown): value is FilesystemTopologySnapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<FilesystemTopologySnapshot>;
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.sessions) && typeof candidate.generatedAt === "string";
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

function nodeName(path: string) {
  return path === "/" ? "/" : path.split("/").filter(Boolean).at(-1) ?? path;
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
  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);

  const refresh = useCallback(async () => {
    setRegionStatus((current) => snapshot ? "refreshing" : current === "error" ? "loading" : current);
    try {
      const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
      if (!response.ok) throw new Error("Topology request failed");
      const data: unknown = await response.json();
      if (!isSnapshot(data)) throw new Error("Topology response unavailable");
      setSnapshot(data);
      setRegionStatus("ready");
      setSelectedSessionId((current) => current && data.sessions.some((session) => session.sessionId === current) ? current : data.sessions[0]?.sessionId ?? null);
      setSelectedPath((current) => current && data.nodes.some((node) => node.path === current) ? current : data.nodes[0]?.path ?? null);
    } catch {
      setRegionStatus(snapshot ? "stale" : "error");
    }
  }, [snapshot]);

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
        setSnapshot(data);
        setRegionStatus("ready");
      } catch {
        if (!disposed) setRegionStatus((current) => current === "ready" ? "stale" : "error");
      }
    };
    const connect = () => {
      source = new EventSource("/api/filesystem-topology/stream");
      source.addEventListener("snapshot", onMessage as EventListener);
      source.addEventListener("topology.update", onMessage as EventListener);
      source.onopen = () => { if (!disposed) setStreamState("live"); };
      source.onerror = () => {
        if (disposed || source === null) return;
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
        setSnapshot(data);
        setRegionStatus("ready");
        setStreamState("live");
      } catch { /* retain the last valid topology */ }
    };
    connect();
    return () => {
      disposed = true;
      source?.close();
      if (retry !== null) window.clearTimeout(retry);
    };
  }, []);

  const loadHistory = useCallback(async (sessionId: string, cursor: string | null, append = false) => {
    setHistoryStatus(append ? "refreshing" : "loading");
    try {
      const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/cwd-history${params}`, { cache: "no-store" });
      if (!response.ok) throw new Error("History request failed");
      const data: unknown = await response.json();
      if (!isHistoryPage(data)) throw new Error("History response unavailable");
      setHistory((current) => append ? [...current, ...data.items] : data.items);
      setHistoryCursor(data.nextCursor);
      setHistoryStatus("ready");
    } catch {
      setHistoryStatus("error");
    }
  }, []);

  useEffect(() => {
    if (!selectedSessionId) {
      return;
    }
    const request = window.setTimeout(() => { void loadHistory(selectedSessionId, null); }, 0);
    return () => window.clearTimeout(request);
  }, [loadHistory, selectedSessionId]);

  const selectedSession = useMemo(() => snapshot?.sessions.find((session) => session.sessionId === selectedSessionId) ?? null, [selectedSessionId, snapshot]);
  const selectedNode = useMemo(() => snapshot?.nodes.find((node) => node.path === selectedPath) ?? null, [selectedPath, snapshot]);
  const sessionById = useMemo(() => new Map(snapshot?.sessions.map((session) => [session.sessionId, session])), [snapshot]);
  const tree = useMemo(() => {
    const children = new Map<string | null, FilesystemTopologyNode[]>();
    for (const node of snapshot?.nodes ?? []) {
      const group = children.get(node.parentPath) ?? [];
      group.push(node);
      children.set(node.parentPath, group);
    }
    for (const group of children.values()) group.sort((left, right) => left.path.localeCompare(right.path));
    return children;
  }, [snapshot]);

  const selectSession = (sessionId: string) => {
    const session = sessionById.get(sessionId);
    setSelectedSessionId(sessionId);
    if (session?.cwdState.path) setSelectedPath(session.cwdState.path);
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

  const renderNode = (node: FilesystemTopologyNode) => {
    const children = tree.get(node.path) ?? [];
    const isSelected = node.path === selectedPath;
    return <li key={node.path} className="relative pl-7 before:absolute before:left-3 before:top-0 before:h-1/2 before:w-px before:bg-border after:absolute after:left-3 after:top-1/2 after:h-px after:w-4 after:bg-border first:before:hidden">
      <button type="button" role="treeitem" aria-selected={isSelected} onClick={() => setSelectedPath(node.path)} className={`group flex min-h-10 min-w-52 items-center gap-2 rounded-lg border px-3 text-left text-sm transition-colors duration-150 ${isSelected ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"}`}>
        {children.length ? <FolderOpen className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" /> : <Folder className="h-4 w-4 shrink-0 text-text-subtle group-hover:text-primary" aria-hidden="true" />}
        <span className="font-mono text-xs">{nodeName(node.path)}</span>
        {node.sessionIds.length > 0 && <span className="ml-auto inline-flex min-w-5 items-center justify-center rounded-full bg-info-subtle px-1.5 text-xs font-semibold text-info" aria-label={`${node.sessionIds.length} observed sessions`}>{node.sessionIds.length}</span>}
      </button>
      {children.length > 0 && <ul role="group" className="ml-6 border-l border-border py-2">{children.map(renderNode)}</ul>}
    </li>;
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
        <button type="button" className="ui-button" onClick={() => void refresh()} disabled={regionStatus === "loading" || regionStatus === "refreshing"}><RefreshCw className={`h-4 w-4 ${regionStatus === "refreshing" ? "animate-spin" : ""}`} aria-hidden="true" />Refresh</button>
      </div>
    </section>

    <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="ui-panel overflow-hidden" aria-busy={regionStatus === "loading"}>
        <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2"><Route className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold text-text">Observed path topology</h2></div>
            <p className="mt-1 text-xs text-text-subtle">Only paths received from canonical CWD telemetry and their required ancestors are shown.</p>
          </div>
          <div className="flex items-center gap-1">
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(0.7, Number((value - 0.1).toFixed(1))))}><ZoomOut className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Reset topology view" onClick={resetViewport}><MousePointer2 className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.4, Number((value + 0.1).toFixed(1))))}><ZoomIn className="h-4 w-4" /></button>
          </div>
        </div>
        {regionStatus === "error" ? <div className="p-5"><RegionState kind="error" title="Filesystem activity unavailable" description="The topology could not be loaded. Other dashboard views remain available." /></div> : regionStatus === "loading" && !snapshot ? <div className="p-5"><RegionState kind="loading" title="Loading filesystem activity" /></div> : !snapshot?.nodes.length ? <div className="p-5"><RegionState kind="empty" title="No observed working directories yet" description="The live view will populate after the canonical pipeline records Cowrie CWD telemetry." /></div> : <>
          <div className="relative min-h-[420px] overflow-hidden bg-surface-subtle p-5 sm:p-8" onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerEnd} onPointerCancel={onPointerEnd}>
            <div className="pointer-events-none absolute inset-0 opacity-50 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px]" aria-hidden="true" />
            <div className="pointer-events-none absolute left-5 top-5 flex items-center gap-2 text-xs text-text-subtle"><Grip className="h-3.5 w-3.5" aria-hidden="true" />Drag surface to pan</div>
            <motion.div className="relative origin-top-left pt-9" animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }} style={reducedMotion ? { transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` } : undefined} transition={{ type: "spring", stiffness: 260, damping: 28 }}>
              <ul role="tree" aria-label="Observed Cowrie filesystem tree" className="w-max min-w-full py-4">{(tree.get(null) ?? []).map(renderNode)}</ul>
            </motion.div>
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-border px-5 py-3 text-xs text-text-muted"><span><strong className="text-text">{snapshot.nodes.length}</strong> observed paths</span><span><strong className="text-text">{snapshot.sessions.length}</strong> sessions with a known CWD</span><span>Snapshot {formatTimestamp(snapshot.generatedAt)}</span></div>
        </>}
      </div>

      <aside className="ui-panel h-fit p-5" aria-live="polite">
        <div className="flex items-center gap-2"><CircleDot className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Path inspector</h2></div>
        {selectedNode ? <>
          <p className="mt-5 break-all font-mono text-sm text-text">{selectedNode.path}</p>
          <dl className="mt-5 space-y-3 text-sm"><div className="flex justify-between gap-4"><dt className="text-text-subtle">Observed sessions</dt><dd className="font-semibold text-text">{selectedNode.sessionIds.length}</dd></div><div className="flex justify-between gap-4"><dt className="text-text-subtle">Latest observation</dt><dd className="text-right text-text-muted">{formatTimestamp(selectedNode.observedAt)}</dd></div></dl>
          <div className="mt-6 border-t border-border pt-4"><p className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Sessions at this path</p><div className="space-y-2">{selectedNode.sessionIds.map((id) => { const session = sessionById.get(id); return <button key={id} type="button" onClick={() => selectSession(id)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors ${id === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border hover:bg-surface-hover"}`}><span className="min-w-0 truncate font-mono text-xs text-text">{id}</span><ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" /><span className="sr-only">{session?.sourceIp}</span></button>; })}</div></div>
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
