"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  DEFAULT_STALE_THRESHOLD_MS,
  getFreshnessState,
  SnapshotIngestionCoordinator,
  type FreshnessState,
  type SnapshotTransitionState,
} from "@/lib/filesystem-freshness";
import {
  type StreamState,
} from "./filesystemUtils";
import { FilesystemStreamLifecycleManager } from "./filesystemStreamManager";
import {
  FilesystemRefreshLifecycleManager,
  type RefreshStatus,
} from "./filesystemRefreshManager";

const defaultGetNow = () => Date.now();

export interface UseFilesystemStreamingOptions {
  onSnapshotApplied?: (snapshot: FilesystemTopologySnapshot) => void;
  getNow?: () => number;
  fetchRefresh?: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface UseFilesystemStreamingReturn {
  snapshot: FilesystemTopologySnapshot | null;
  snapshotReceivedAtMs: number | null;
  regionStatus: RegionStatus;
  setRegionStatus: React.Dispatch<React.SetStateAction<RegionStatus>>;
  streamState: StreamState;
  setStreamState: React.Dispatch<React.SetStateAction<StreamState>>;
  isHydrated: boolean;
  setIsHydrated: React.Dispatch<React.SetStateAction<boolean>>;
  lastUpdateAgeMs: number;
  telemetryAgeMs: number | null;
  snapshotReceiptAgeMs: number;
  retrievalAgeMs: number;
  serverGenerationAgeMs: number;
  latestTelemetryAt: string | null;
  freshnessState: FreshnessState;
  refresh: () => Promise<void>;
  handleReconnect: () => void;
  applySnapshot: (data: FilesystemTopologySnapshot, explicitReceivedAtMs?: number) => boolean;
  refreshStatus: RefreshStatus;
  refreshError: string | null;
}

const INITIAL_TRANSITION_STATE: SnapshotTransitionState = {
  envelope: {
    snapshot: null,
    snapshotReceivedAtMs: null,
  },
  latestSnapshotAt: 0,
  trustMarker: null,
};

export function useFilesystemStreaming(
  options: UseFilesystemStreamingOptions = {},
): UseFilesystemStreamingReturn {
  const { onSnapshotApplied, getNow = defaultGetNow } = options;

  const getNowRef = useRef(getNow);
  useEffect(() => {
    getNowRef.current = getNow;
  }, [getNow]);

  const coordinatorRef = useRef<SnapshotIngestionCoordinator | null>(null);
  if (coordinatorRef.current === null) {
    coordinatorRef.current = new SnapshotIngestionCoordinator(INITIAL_TRANSITION_STATE);
  }

  const [transitionState, setTransitionState] = useState<SnapshotTransitionState>(INITIAL_TRANSITION_STATE);
  const snapshot = transitionState.envelope.snapshot;
  const snapshotReceivedAtMs = transitionState.envelope.snapshotReceivedAtMs;

  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [isHydrated, setIsHydrated] = useState(false);

  const reconnectStreamRef = useRef<(() => void) | null>(null);
  const onSnapshotAppliedRef = useRef(onSnapshotApplied);

  useEffect(() => {
    onSnapshotAppliedRef.current = onSnapshotApplied;
  }, [onSnapshotApplied]);

  // applySnapshot has stable identity (empty dependency array)
  // Evaluates acceptance synchronously against coordinatorRef, deterministically
  // updating state and firing side effects only on genuine acceptance
  const applySnapshot = useCallback((data: FilesystemTopologySnapshot, explicitReceivedAtMs?: number): boolean => {
    const receivedAtMs = typeof explicitReceivedAtMs === "number"
      ? explicitReceivedAtMs
      : (getNowRef.current ? getNowRef.current() : Date.now());

    const result = coordinatorRef.current!.ingest(data, receivedAtMs);
    if (result.accepted) {
      setTransitionState(result.state);
      setRegionStatus("ready");
      onSnapshotAppliedRef.current?.(data);
      return true;
    }
    return false;
  }, []);

  const applySnapshotRef = useRef(applySnapshot);
  useEffect(() => {
    applySnapshotRef.current = applySnapshot;
  }, [applySnapshot]);

  const [refreshState, setRefreshState] = useState<{ status: RefreshStatus; error: string | null }>({
    status: "idle",
    error: null,
  });

  const refreshManagerRef = useRef<FilesystemRefreshLifecycleManager | null>(null);

  // Initialize refresh manager and abort in-flight refresh on component unmount
  useEffect(() => {
    const manager = new FilesystemRefreshLifecycleManager({
      fetchSnapshot: options.fetchRefresh,
      hasSnapshot: () => Boolean(coordinatorRef.current?.getState().envelope.snapshot),
      applySnapshot: (snap) => applySnapshotRef.current(snap),
      onRegionStatus: (st) => setRegionStatus(st),
      onRefreshStatus: (st, err) => setRefreshState({ status: st, error: err?.message ?? null }),
    });
    refreshManagerRef.current = manager;

    return () => {
      refreshManagerRef.current = null;
      manager.dispose();
    };
  }, [options.fetchRefresh]);

  const refresh = useCallback(async () => {
    if (!refreshManagerRef.current) {
      refreshManagerRef.current = new FilesystemRefreshLifecycleManager({
        fetchSnapshot: options.fetchRefresh,
        hasSnapshot: () => Boolean(coordinatorRef.current?.getState().envelope.snapshot),
        applySnapshot: (snap) => applySnapshotRef.current(snap),
        onRegionStatus: (st) => setRegionStatus(st),
        onRefreshStatus: (st, err) => setRefreshState({ status: st, error: err?.message ?? null }),
      });
    }
    await refreshManagerRef.current.refresh();
  }, [options.fetchRefresh]);

  const handleReconnect = useCallback(() => {
    reconnectStreamRef.current?.();
    void refresh();
  }, [refresh]);

  // Stable 1-second interval timer that does not re-subscribe or restart when getNow changes
  const [now, setNow] = useState(() => (getNow ? getNow() : Date.now()));
  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(getNowRef.current ? getNowRef.current() : Date.now());
    }, 1_000);
    return () => window.clearInterval(timer);
  }, []);

  const {
    telemetryAt,
    telemetryAgeMs,
    telemetryStatus,
    snapshotReceiptAgeMs,
    retrievalAgeMs,
    serverGenerationAgeMs,
    hasTelemetry,
  } = useMemo(() => {
    return calculateTelemetryAge({
      snapshot,
      snapshotReceivedAtMs,
      now,
      trustMarker: transitionState.trustMarker,
    });
  }, [snapshot, snapshotReceivedAtMs, now, transitionState.trustMarker]);

  const freshnessState = useMemo(() => {
    return getFreshnessState({
      telemetryAgeMs,
      telemetryStatus,
      snapshotReceiptAgeMs,
      retrievalAgeMs,
      hasTelemetry,
      staleThresholdMs: DEFAULT_STALE_THRESHOLD_MS,
      streamState,
      regionStatus,
      hasSnapshot: Boolean(snapshot),
    });
  }, [telemetryAgeMs, telemetryStatus, snapshotReceiptAgeMs, retrievalAgeMs, hasTelemetry, streamState, regionStatus, snapshot]);

  // SSE Stream subscription managed by lifecycle manager;
  // Does not restart across connecting -> live transitions, getNow identity shifts, or age timer ticks
  useEffect(() => {
    const manager = new FilesystemStreamLifecycleManager({
      onSnapshot: (data) => applySnapshotRef.current(data),
      onStreamState: setStreamState,
      onRegionStatus: (updater) => setRegionStatus(updater),
      onHydrated: () => setIsHydrated(true),
    });

    reconnectStreamRef.current = () => manager.reconnect();
    manager.connect();

    return () => {
      reconnectStreamRef.current = null;
      manager.dispose();
    };
  }, []);

  return {
    snapshot,
    snapshotReceivedAtMs,
    regionStatus,
    setRegionStatus,
    streamState,
    setStreamState,
    isHydrated,
    setIsHydrated,
    lastUpdateAgeMs: telemetryAgeMs ?? snapshotReceiptAgeMs,
    telemetryAgeMs,
    snapshotReceiptAgeMs,
    retrievalAgeMs,
    serverGenerationAgeMs,
    latestTelemetryAt: telemetryAt,
    freshnessState,
    refresh,
    handleReconnect,
    applySnapshot,
    refreshStatus: refreshState.status,
    refreshError: refreshState.error,
  };
}
