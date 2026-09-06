"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import {
  isDashboardThreatEvent,
  parseThreatStreamMessage,
  type DashboardThreatEvent,
} from "@/lib/dashboardTypes";

interface ThreatFeedContextValue {
  threats: DashboardThreatEvent[];
  status: RegionStatus;
  lastUpdated: number | null;
  refresh: () => Promise<void>;
}

const ThreatFeedContext = createContext<ThreatFeedContextValue | null>(null);
const REST_FALLBACK_INTERVAL_MS = 15_000;
const SSE_RETRY_MS = 5_000;
const MAX_THREATS = 100;

function sortThreats(threats: DashboardThreatEvent[]) {
  return [...threats].sort((left, right) => {
    return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
  }).slice(0, MAX_THREATS);
}

function upsertThreat(threats: DashboardThreatEvent[], incoming: DashboardThreatEvent) {
  const index = threats.findIndex((threat) => threat.id === incoming.id);
  if (index === -1) return sortThreats([incoming, ...threats]);
  const next = [...threats];
  next[index] = incoming;
  return sortThreats(next);
}

export function ThreatFeedProvider({ children }: { children: React.ReactNode }) {
  const [threats, setThreats] = useState<DashboardThreatEvent[]>([]);
  const [status, setStatus] = useState<RegionStatus>("loading");
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const hasSnapshot = useRef(false);
  const streamConnected = useRef(false);

  const fetchSnapshot = useCallback(async () => {
    setStatus(hasSnapshot.current ? "refreshing" : "loading");
    try {
      const response = await fetch("/api/threats", { cache: "no-store" });
      if (!response.ok) throw new Error("Threat request failed");
      const data: unknown = await response.json();
      if (!Array.isArray(data)) throw new Error("Threat response unavailable");

      setThreats(sortThreats(data.filter(isDashboardThreatEvent)));
      hasSnapshot.current = true;
      setLastUpdated(Date.now());
      setStatus(streamConnected.current ? "ready" : "stale");
    } catch {
      setStatus(hasSnapshot.current ? "stale" : "error");
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    let reconnectTimer: number | null = null;
    let fallbackTimer: number | null = null;

    const stopFallback = () => {
      if (fallbackTimer === null) return;
      window.clearInterval(fallbackTimer);
      fallbackTimer = null;
    };

    const startFallback = () => {
      if (fallbackTimer !== null) return;
      void fetchSnapshot();
      fallbackTimer = window.setInterval(() => void fetchSnapshot(), REST_FALLBACK_INTERVAL_MS);
    };

    const scheduleReconnect = () => {
      if (disposed || reconnectTimer !== null) return;
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, SSE_RETRY_MS);
    };

    const handleMessage = (event: MessageEvent<string>) => {
      try {
        const message = parseThreatStreamMessage(JSON.parse(event.data));
        if (!message) return;

        if (message.type === "snapshot") {
          setThreats(sortThreats(message.data));
          hasSnapshot.current = true;
          setLastUpdated(Date.now());
          setStatus("ready");
          return;
        }

        if (message.type === "threat.upsert") {
          setThreats((current) => upsertThreat(current, message.data));
          hasSnapshot.current = true;
          setLastUpdated(Date.now());
          setStatus("ready");
        }
      } catch {
        // Ignore a malformed event and retain the last valid snapshot.
      }
    };

    const connect = () => {
      if (disposed) return;
      source?.close();
      const connection = new EventSource("/api/threats/stream");
      source = connection;
      connection.addEventListener("snapshot", handleMessage as EventListener);
      connection.addEventListener("threat.upsert", handleMessage as EventListener);
      connection.addEventListener("heartbeat", handleMessage as EventListener);
      connection.onopen = () => {
        if (disposed) return;
        streamConnected.current = true;
        stopFallback();
        if (hasSnapshot.current) setStatus("ready");
      };
      connection.onerror = () => {
        if (disposed || source !== connection) return;
        streamConnected.current = false;
        connection.close();
        source = null;
        setStatus(hasSnapshot.current ? "stale" : "error");
        startFallback();
        scheduleReconnect();
      };
    };

    void fetchSnapshot();
    connect();

    return () => {
      disposed = true;
      streamConnected.current = false;
      source?.close();
      stopFallback();
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
    };
  }, [fetchSnapshot]);

  const value = useMemo<ThreatFeedContextValue>(() => ({
    threats,
    status,
    lastUpdated,
    refresh: fetchSnapshot,
  }), [fetchSnapshot, lastUpdated, status, threats]);

  return <ThreatFeedContext.Provider value={value}>{children}</ThreatFeedContext.Provider>;
}

export function useThreatFeed(): ThreatFeedContextValue {
  const context = useContext(ThreatFeedContext);
  if (!context) throw new Error("useThreatFeed must be used within ThreatFeedProvider");
  return context;
}
