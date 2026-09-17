"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  DEFAULT_STALE_THRESHOLD_MS,
  getFreshnessState,
  isSnapshot,
  type FreshnessState,
  type StreamState,
} from "./filesystemUtils";

export interface UseFilesystemStreamingOptions {
  onSnapshotApplied?: (snapshot: FilesystemTopologySnapshot) => void;
  getNow?: () => number;
}

interface SnapshotEnvelope {
  snapshot: FilesystemTopologySnapshot | null;
  snapshotReceivedAtMs: number | null;
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
  const { onSnapshotApplied, getNow = () => Date.now() } = options;

  const [envelope, setEnvelope] = useState<SnapshotEnvelope>({
    snapshot: null,
    snapshotReceivedAtMs: null,
  });
  const snapshot = envelope.snapshot;
  const snapshotReceivedAtMs = envelope.snapshotReceivedAtMs;

  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [isHydrated, setIsHydrated] = useState(false);

  const latestSnapshotAt = useRef(0);
  const reconnectStreamRef = useRef<(() => void) | null>(null);
  const onSnapshotAppliedRef = useRef(onSnapshotApplied);

  useEffect(() => {
    onSnapshotAppliedRef.current = onSnapshotApplied;
  }, [onSnapshotApplied]);

  const applySnapshot = useCallback((data: FilesystemTopologySnapshot, explicitReceivedAtMs?: number): boolean => {
    const timestamp = Date.parse(data.generatedAt) || 0;
    if (timestamp && timestamp < latestSnapshotAt.current) return false;
    latestSnapshotAt.current = Math.max(latestSnapshotAt.current, timestamp);

    const receivedAtMs = typeof explicitReceivedAtMs === "number" ? explicitReceivedAtMs : getNow();
    setEnvelope({
      snapshot: data,
      snapshotReceivedAtMs: receivedAtMs,
    });
    setRegionStatus("ready");
    onSnapshotAppliedRef.current?.(data);
    return true;
  }, [getNow]);

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

  const handleReconnect = useCallback(() => {
    reconnectStreamRef.current?.();
    void refresh();
  }, [refresh]);

  const [now, setNow] = useState(() => getNow());
  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(getNow());
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [getNow]);

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
    });
  }, [snapshot, snapshotReceivedAtMs, now]);

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
      if (retry !== null) {
        window.clearTimeout(retry);
        retry = null;
      }
      source?.close();
      setStreamState("connecting");
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

    reconnectStreamRef.current = () => {
      if (!disposed) {
        connect();
      }
    };

    connect();
    return () => {
      disposed = true;
      reconnectStreamRef.current = null;
      source?.close();
      if (retry !== null) window.clearTimeout(retry);
    };
  }, [applySnapshot]);

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
