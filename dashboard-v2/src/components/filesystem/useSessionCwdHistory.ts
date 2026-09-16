"use client";

import { useCallback, useRef, useState } from "react";

import type { RegionStatus } from "@/components/ui/RegionState";
import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { isHistoryPage } from "./filesystemUtils";

export interface UseSessionCwdHistoryOptions {
  requestedHopRef?: React.MutableRefObject<string | null>;
  onSelectHistoryEventId?: (id: string | null) => void;
}

export interface UseSessionCwdHistoryReturn {
  history: SessionCwdHistoryEvent[];
  setHistory: React.Dispatch<React.SetStateAction<SessionCwdHistoryEvent[]>>;
  historyCursor: string | null;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  historyComplete: boolean;
  historyStatus: RegionStatus;
  loadHistory: (sessionId: string, cursor: string | null, append?: boolean) => Promise<void>;
  resetHistory: () => void;
}

export function useSessionCwdHistory(
  options: UseSessionCwdHistoryOptions = {},
): UseSessionCwdHistoryReturn {
  const { requestedHopRef, onSelectHistoryEventId } = options;

  const [history, setHistory] = useState<SessionCwdHistoryEvent[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyTotalItems, setHistoryTotalItems] = useState(0);
  const [historyTotalSuccessfulItems, setHistoryTotalSuccessfulItems] = useState(0);
  const [historyComplete, setHistoryComplete] = useState(true);
  const [historyStatus, setHistoryStatus] = useState<RegionStatus>("loading");

  const historyRequest = useRef<{ generation: number; sessionId: string; controller: AbortController } | null>(null);
  const lastHistorySessionId = useRef<string | null>(null);

  const resetHistory = useCallback(() => {
    historyRequest.current?.controller.abort();
    historyRequest.current = null;
    lastHistorySessionId.current = null;
    setHistory([]);
    setHistoryCursor(null);
    setHistoryTotalItems(0);
    setHistoryTotalSuccessfulItems(0);
    setHistoryComplete(true);
    setHistoryStatus("ready");
  }, []);

  const loadHistory = useCallback(
    async (sessionId: string, cursor: string | null, append = false) => {
      const generation = (historyRequest.current?.generation ?? 0) + 1;
      historyRequest.current?.controller.abort();
      const controller = new AbortController();
      historyRequest.current = { generation, sessionId, controller };
      const isNewSession = sessionId !== lastHistorySessionId.current;
      lastHistorySessionId.current = sessionId;

      if (!append && isNewSession) {
        setHistory([]);
        setHistoryCursor(null);
        setHistoryTotalItems(0);
        setHistoryTotalSuccessfulItems(0);
        setHistoryComplete(true);
        if (!requestedHopRef?.current) {
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

        setHistory((current) => (append ? [...current, ...data.items] : data.items));
        setHistoryCursor(data.nextCursor);
        setHistoryTotalItems(data.totalItems);
        setHistoryTotalSuccessfulItems(data.totalSuccessfulItems);
        setHistoryComplete(data.complete);
        setHistoryStatus("ready");

        if (requestedHopRef?.current) {
          if (data.items.some((item) => item.id === requestedHopRef.current)) {
            onSelectHistoryEventId?.(requestedHopRef.current);
          }
          requestedHopRef.current = null;
        }
      } catch {
        if (controller.signal.aborted || historyRequest.current?.generation !== generation) return;
        setHistoryStatus("error");
      }
    },
    [onSelectHistoryEventId, requestedHopRef],
  );

  return {
    history,
    setHistory,
    historyCursor,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    historyStatus,
    loadHistory,
    resetHistory,
  };
}
