"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  DEFAULT_STALE_THRESHOLD_MS,
  getFreshnessState,
  processSnapshotTransition,
  TelemetryFreshnessTracker,
  type FreshnessState,
  type SnapshotTransitionState,
} from "@/lib/filesystem-freshness";
import {
  isSnapshot,
  type StreamState,
} from "./filesystemUtils";
import { FilesystemStreamLifecycleManager } from "./filesystemStreamManager";

const defaultGetNow = () => Date.now();

export interface UseFilesystemStreamingOptions {
  onSnapshotApplied?: (snapshot: FilesystemTopologySnapshot) => void;
  getNow?: () => number;
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
}

export function useFilesystemStreaming(
  options: UseFilesystemStreamingOptions = {},
): UseFilesystemStreamingReturn {
  const { onSnapshotApplied, getNow = defaultGetNow } = options;

  const getNowRef = useRef(getNow);
  useEffect(() => {
    getNowRef.current = getNow;
  }, [getNow]);

  const [transitionState, setTransitionState] = useState<SnapshotTransitionState>({
    envelope: {
      snapshot: null,
      snapshotReceivedAtMs: null,
    },
    latestSnapshotAt: 0,
  });
  const snapshot = transitionState.envelope.snapshot;
  const snapshotReceivedAtMs = transitionState.envelope.snapshotReceivedAtMs;

  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [isHydrated, setIsHydrated] = useState(false);

  const reconnectStreamRef = useRef<(() => void) | null>(null);
  const onSnapshotAppliedRef = useRef(onSnapshotApplied);
  const [freshnessTracker] = useState(() => new TelemetryFreshnessTracker());

  useEffect(() => {
    onSnapshotAppliedRef.current = onSnapshotApplied;
  }, [onSnapshotApplied]);

  // applySnapshot has stable identity (empty dependency array)
  const applySnapshot = useCallback((data: FilesystemTopologySnapshot, explicitReceivedAtMs?: number): boolean => {
    const receivedAtMs = typeof explicitReceivedAtMs === "number"
      ? explicitReceivedAtMs
      : (getNowRef.current ? getNowRef.current() : Date.now());

    let wasAccepted = false;
    setTransitionState((prev) => {
      const result = processSnapshotTransition(prev, data, receivedAtMs);
      wasAccepted = result.accepted;
      return result.accepted ? result.state : prev;
    });

    if (wasAccepted) {
      setRegionStatus("ready");
      onSnapshotAppliedRef.current?.(data);
    }
    return wasAccepted;
  }, []);

  const applySnapshotRef = useRef(applySnapshot);
  useEffect(() => {
    applySnapshotRef.current = applySnapshot;
  }, [applySnapshot]);

  const refresh = useCallback(async () => {
    setRegionStatus((current) => (transitionState.envelope.snapshot ? "refreshing" : current === "error" ? "loading" : current));
    try {
      const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
      if (!response.ok) throw new Error("Topology request failed");
      const data: unknown = await response.json();
      if (!isSnapshot(data)) throw new Error("Topology response unavailable");
      applySnapshotRef.current(data);
    } catch {
      setRegionStatus((current) => (current === "refreshing" || current === "ready" ? "stale" : "error"));
    }
  }, [transitionState.envelope.snapshot]);

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
      freshnessTracker,
    });
  }, [snapshot, snapshotReceivedAtMs, now, freshnessTracker]);

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
  };
}
