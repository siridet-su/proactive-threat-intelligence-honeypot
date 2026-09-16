"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { isHistoryPage } from "./filesystemUtils";
import {
  mergeResolvedHistoryEvent,
  SessionHopLifecycleManager,
  type HopResolutionStatus,
  type SessionCwdHopPayload,
} from "./sessionHopResolver";

export type { HopResolutionStatus };

export interface UseSessionCwdHistoryOptions {
  requestedHopRef?: React.MutableRefObject<string | null>;
  onSelectHistoryEventId?: (id: string | null) => void;
  viewMode?: "live" | "audit";
  fetchHop?: (sessionId: string, hopId: string, signal: AbortSignal) => Promise<SessionCwdHopPayload>;
}

export interface UseSessionCwdHistoryReturn {
  history: SessionCwdHistoryEvent[];
  setHistory: React.Dispatch<React.SetStateAction<SessionCwdHistoryEvent[]>>;
  historyCursor: string | null;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  historyComplete: boolean;
  historyStatus: RegionStatus;
  hopResolutionStatus: HopResolutionStatus;
  requestedHop: string | null;
  clearRequestedHop: () => void;
  selectLatestHop: () => void;
  loadHistory: (sessionId: string, cursor: string | null, append?: boolean) => Promise<void>;
  resetHistory: () => void;
}

export function useSessionCwdHistory(
  options: UseSessionCwdHistoryOptions = {},
): UseSessionCwdHistoryReturn {
  const { requestedHopRef, onSelectHistoryEventId, viewMode = "live", fetchHop } = options;

  const [history, setHistory] = useState<SessionCwdHistoryEvent[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyTotalItems, setHistoryTotalItems] = useState(0);
  const [historyTotalSuccessfulItems, setHistoryTotalSuccessfulItems] = useState(0);
  const [historyComplete, setHistoryComplete] = useState(true);
  const [historyStatus, setHistoryStatus] = useState<RegionStatus>("loading");
  const [hopResolutionStatus, setHopResolutionStatus] = useState<HopResolutionStatus>("idle");
  const [requestedHop, setRequestedHop] = useState<string | null>(null);

  const historyRequest = useRef<{ generation: number; sessionId: string; controller: AbortController } | null>(null);
  const lastHistorySessionId = useRef<string | null>(null);
  const hopManagerRef = useRef<SessionHopLifecycleManager | null>(null);

  if (hopManagerRef.current == null) {
    hopManagerRef.current = new SessionHopLifecycleManager();
  }

  // Abort resolution if view mode transitions out of audit
  useEffect(() => {
    if (viewMode !== "audit") {
      hopManagerRef.current?.abort();
    }
  }, [viewMode]);

  // Clean up upon unmount
  useEffect(() => {
    return () => {
      hopManagerRef.current?.destroy();
    };
  }, []);

  const resetHistory = useCallback(() => {
    historyRequest.current?.controller.abort();
    historyRequest.current = null;
    lastHistorySessionId.current = null;
    hopManagerRef.current?.destroy();
    setHistory([]);
    setHistoryCursor(null);
    setHistoryTotalItems(0);
    setHistoryTotalSuccessfulItems(0);
    setHistoryComplete(true);
    setHistoryStatus("ready");
    setHopResolutionStatus("idle");
    setRequestedHop(null);
  }, []);

  const clearRequestedHop = useCallback(() => {
    if (requestedHopRef) {
      requestedHopRef.current = null;
    }
    setRequestedHop(null);
    hopManagerRef.current?.destroy();
    setHopResolutionStatus("idle");
    onSelectHistoryEventId?.(null);
  }, [onSelectHistoryEventId, requestedHopRef]);

  const selectLatestHop = useCallback(() => {
    if (requestedHopRef) {
      requestedHopRef.current = null;
    }
    setRequestedHop(null);
    hopManagerRef.current?.destroy();
    setHopResolutionStatus("idle");
    const latestId = history[0]?.id ?? null;
    onSelectHistoryEventId?.(latestId);
  }, [history, onSelectHistoryEventId, requestedHopRef]);

  const loadHistory = useCallback(
    async (sessionId: string, cursor: string | null, append = false) => {
      const generation = (historyRequest.current?.generation ?? 0) + 1;
      historyRequest.current?.controller.abort();
      const controller = new AbortController();
      historyRequest.current = { generation, sessionId, controller };
      const isNewSession = sessionId !== lastHistorySessionId.current;
      lastHistorySessionId.current = sessionId;

      const currentHop = requestedHopRef?.current ?? null;

      if (!append && isNewSession) {
        setHistory([]);
        setHistoryCursor(null);
        setHistoryTotalItems(0);
        setHistoryTotalSuccessfulItems(0);
        setHistoryComplete(true);
        if (!currentHop) {
          onSelectHistoryEventId?.(null);
        }
      }

      setHistoryStatus(append || !isNewSession ? "refreshing" : "loading");

      try {
        const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
        const response = await fetch(
          `/api/sessions/${encodeURIComponent(sessionId)}/cwd-history${params}`,
          {
            cache: "no-store",
            signal: controller.signal,
          },
        );
        if (!response.ok) throw new Error("History request failed");
        const data: unknown = await response.json();
        if (!isHistoryPage(data)) throw new Error("History response unavailable");

        const active = historyRequest.current;
        if (!active || active.generation !== generation || active.sessionId !== sessionId) return;

        setHistory((current) => {
          if (!append) return data.items;
          const incomingIds = new Set(data.items.map((i) => i.id));
          const existingDeduplicated = current.filter((i) => !incomingIds.has(i.id));
          return [...existingDeduplicated, ...data.items];
        });
        setHistoryCursor(data.nextCursor);
        setHistoryTotalItems(data.totalItems);
        setHistoryTotalSuccessfulItems(data.totalSuccessfulItems);
        setHistoryComplete(data.complete);
        setHistoryStatus("ready");

        if (!append && currentHop) {
          setRequestedHop(currentHop);
          if (data.items.some((item) => item.id === currentHop)) {
            // Found on page one
            setHopResolutionStatus("resolved");
            onSelectHistoryEventId?.(currentHop);
          } else {
            // Older hop: trigger authoritative direct lookup
            setHopResolutionStatus("resolving");
            hopManagerRef.current?.sync({
              sessionId,
              hopId: currentHop,
              viewMode,
              history: data.items,
              fetchHop,
              onStatusChange: (status) => {
                setHopResolutionStatus(status);
              },
              onResolved: (event) => {
                setHistory((current) => mergeResolvedHistoryEvent(current, event));
                onSelectHistoryEventId?.(event.id);
              },
            });
          }
        }
      } catch {
        if (controller.signal.aborted || historyRequest.current?.generation !== generation) return;
        setHistoryStatus("error");
      }
    },
    [fetchHop, onSelectHistoryEventId, requestedHopRef, viewMode],
  );

  return {
    history,
    setHistory,
    historyCursor,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    historyStatus,
    hopResolutionStatus: viewMode === "audit" ? hopResolutionStatus : "idle",
    requestedHop: viewMode === "audit" ? requestedHop : null,
    clearRequestedHop,
    selectLatestHop,
    loadHistory,
    resetHistory,
  };
}
