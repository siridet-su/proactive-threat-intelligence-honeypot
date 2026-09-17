"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { isHistoryPage } from "./filesystemUtils";
import {
  SessionHopLifecycleManager,
  type HopResolutionStatus,
  type SessionCwdHopPayload,
} from "./sessionHopResolver";

export type { HopResolutionStatus };

export interface UseSessionCwdHistoryOptions {
  requestedHopRef?: React.MutableRefObject<string | null>;
  onSelectHistoryEventId?: (id: string | null, source?: "user" | "playback" | "sync") => void;
  viewMode?: "live" | "audit";
  fetchHop?: (sessionId: string, hopId: string, signal: AbortSignal) => Promise<SessionCwdHopPayload>;
}

export interface UseSessionCwdHistoryReturn {
  history: SessionCwdHistoryEvent[];
  setHistory: React.Dispatch<React.SetStateAction<SessionCwdHistoryEvent[]>>;
  anchoredHop: SessionCwdHistoryEvent | null;
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
  const [anchoredHop, setAnchoredHop] = useState<SessionCwdHistoryEvent | null>(null);
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
    setAnchoredHop(null);
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
    setAnchoredHop(null);
    hopManagerRef.current?.destroy();
    setHopResolutionStatus("idle");
    onSelectHistoryEventId?.(null, "user");
  }, [onSelectHistoryEventId, requestedHopRef]);

  const selectLatestHop = useCallback(() => {
    if (requestedHopRef) {
      requestedHopRef.current = null;
    }
    setRequestedHop(null);
    setAnchoredHop(null);
    hopManagerRef.current?.destroy();
    setHopResolutionStatus("idle");
    const latestId = history[0]?.id ?? null;
    onSelectHistoryEventId?.(latestId, "user");
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
        setAnchoredHop(null);
        setHistoryCursor(null);
        setHistoryTotalItems(0);
        setHistoryTotalSuccessfulItems(0);
        setHistoryComplete(true);
        if (!currentHop) {
          onSelectHistoryEventId?.(null, "sync");
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

        if (append) {
          // If earlier pages now include the anchored target, reconcile it
          setAnchoredHop((prev) => {
            if (!prev) return null;
            if (data.items.some((item) => item.id === prev.id)) {
              return null;
            }
            return prev;
          });
        }

        if (!append && currentHop) {
          setRequestedHop(currentHop);
          if (data.items.some((item) => item.id === currentHop)) {
            // Found on page one: clear one-shot request intent
            setHopResolutionStatus("resolved");
            if (requestedHopRef) {
              requestedHopRef.current = null;
            }
            setRequestedHop(null);
            setAnchoredHop(null);
            onSelectHistoryEventId?.(currentHop, "sync");
          } else {
            // Older hop: delegate resolution state strictly to hopManager
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
                // Resolved: clear one-shot request intent while keeping selection
                if (requestedHopRef) {
                  requestedHopRef.current = null;
                }
                setRequestedHop(null);
                setHopResolutionStatus("resolved");
                setAnchoredHop(event);
                onSelectHistoryEventId?.(event.id, "sync");
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
    anchoredHop: viewMode === "audit" ? anchoredHop : null,
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
