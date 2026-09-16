"use client";

import { useCallback, useEffect, useState } from "react";

import type { FilesystemTopologySession, SessionTerminateAction } from "@/lib/dashboardTypes";
import type { OperationToastKind } from "@/components/ui/OperationToast";

export type TerminateCapability = "idle" | "loading" | "available" | "forbidden" | "unconfigured" | "error";
export type { OperationToastKind };

export interface TerminateStatePayload {
  available?: boolean;
  authorized?: boolean;
  configured?: boolean;
  action?: SessionTerminateAction | null;
}

export function terminateCapabilityFrom(document: TerminateStatePayload): TerminateCapability {
  return document.available ? "available" : !document.authorized ? "forbidden" : !document.configured ? "unconfigured" : "error";
}

export interface UseResponseActionOptions {
  selectedSession: FilesystemTopologySession | null;
  sessionIsLive?: boolean;
  enabled?: boolean;
}

export interface UseResponseActionReturn {
  terminateCapability: TerminateCapability;
  terminateAction: SessionTerminateAction | null;
  visibleTerminateAction: SessionTerminateAction | null;
  visibleTerminateCapability: TerminateCapability;
  terminateDialogOpen: boolean;
  setTerminateDialogOpen: React.Dispatch<React.SetStateAction<boolean>>;
  terminateProcessing: boolean;
  terminateError: string | undefined;
  setTerminateError: React.Dispatch<React.SetStateAction<string | undefined>>;
  operationToast: { kind: OperationToastKind; title: string; description: string } | null;
  setOperationToast: React.Dispatch<React.SetStateAction<{ kind: OperationToastKind; title: string; description: string } | null>>;
  handleTerminateSession: () => Promise<void>;
  fetchTerminateState: (sessionId: string, actionId?: string, signal?: AbortSignal) => Promise<TerminateStatePayload>;
}

export function useResponseAction({
  selectedSession,
  sessionIsLive = false,
  enabled = true,
}: UseResponseActionOptions): UseResponseActionReturn {
  const controlSessionId = selectedSession?.sessionId ?? null;

  const [terminateCapability, setTerminateCapability] = useState<TerminateCapability>("idle");
  const [terminateCapabilitySessionId, setTerminateCapabilitySessionId] = useState<string | null>(null);
  const [terminateAction, setTerminateAction] = useState<SessionTerminateAction | null>(null);
  const [terminateDialogOpen, setTerminateDialogOpen] = useState(false);
  const [terminateProcessing, setTerminateProcessing] = useState(false);
  const [terminateError, setTerminateError] = useState<string | undefined>();
  const [operationToast, setOperationToast] = useState<{ kind: OperationToastKind; title: string; description: string } | null>(null);

  const visibleTerminateAction = terminateAction?.sessionId === controlSessionId ? terminateAction : null;
  const visibleTerminateCapability = terminateCapabilitySessionId === controlSessionId ? terminateCapability : "loading";

  const fetchTerminateState = useCallback(async (sessionId: string, actionId?: string, signal?: AbortSignal) => {
    const query = actionId ? `?actionId=${encodeURIComponent(actionId)}` : "";
    const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/actions/terminate${query}`, {
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
    if (!response.ok) throw new Error("Response control status unavailable");
    return (await response.json()) as TerminateStatePayload;
  }, []);

  // Fetch initial state when tab is opened
  useEffect(() => {
    if (!enabled || !controlSessionId) return;
    const controller = new AbortController();
    void fetchTerminateState(controlSessionId, undefined, controller.signal)
      .then((document) => {
        setTerminateAction(document.action ?? null);
        setTerminateCapability(terminateCapabilityFrom(document));
        setTerminateCapabilitySessionId(controlSessionId);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setTerminateCapability("error");
          setTerminateCapabilitySessionId(controlSessionId);
        }
      });
    return () => controller.abort();
  }, [controlSessionId, fetchTerminateState, enabled]);

  // Bounded exponential polling backoff for requested/delivered actions
  useEffect(() => {
    if (!controlSessionId || !visibleTerminateAction || !["requested", "delivered"].includes(visibleTerminateAction.status)) return;
    const controller = new AbortController();
    let timeoutId: number | null = null;
    let currentDelay = !sessionIsLive ? 100 : 1_000;
    const startTime = Date.now();
    const MAX_POLL_DURATION_MS = 24_000;

    const poll = () => {
      void fetchTerminateState(controlSessionId, visibleTerminateAction.actionId, controller.signal)
        .then((document) => {
          if (controller.signal.aborted) return;
          const action = document.action ?? null;
          setTerminateAction(action);
          setTerminateCapability(terminateCapabilityFrom(document));
          setTerminateCapabilitySessionId(controlSessionId);

          if (action?.status === "verified") {
            setOperationToast({
              kind: "success",
              title: "Session disconnected",
              description: "Cowrie emitted the verified session-closed lifecycle event.",
            });
            return;
          }
          if (action?.status === "failed") {
            const description = action.failureCategory
              ? `Action failed: ${action.failureCategory.replace(/_/g, " ")}`
              : "Session termination could not be verified.";
            setOperationToast({
              kind: "error",
              title: "Disconnection failed",
              description,
            });
            return;
          }

          if (Date.now() - startTime < MAX_POLL_DURATION_MS) {
            currentDelay = Math.min(3_500, Math.round(currentDelay * 1.5));
            timeoutId = window.setTimeout(poll, currentDelay);
          }
        })
        .catch(() => {
          if (controller.signal.aborted) return;
          if (Date.now() - startTime < MAX_POLL_DURATION_MS) {
            currentDelay = Math.min(3_500, Math.round(currentDelay * 1.5));
            timeoutId = window.setTimeout(poll, currentDelay);
          }
        });
    };

    timeoutId = window.setTimeout(poll, currentDelay);

    return () => {
      controller.abort();
      if (timeoutId !== null) window.clearTimeout(timeoutId);
    };
  }, [controlSessionId, fetchTerminateState, sessionIsLive, visibleTerminateAction]);

  const handleTerminateSession = useCallback(async () => {
    if (!selectedSession) return;
    setTerminateProcessing(true);
    setTerminateError(undefined);
    try {
      const response = await fetch(`/api/sessions/${encodeURIComponent(selectedSession.sessionId)}/actions/terminate`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmation: selectedSession.sessionId }),
      });
      const document = (await response.json()) as { error?: string; action?: SessionTerminateAction; reconciling?: boolean };
      if (document.action) setTerminateAction(document.action);
      if (!response.ok) throw new Error(document.error ?? "Terminate request failed");
      setTerminateDialogOpen(false);
      setOperationToast(
        document.reconciling
          ? {
              kind: "success",
              title: "Reconciling session state",
              description: "The Pi no longer has this transport. Waiting for Cowrie's closure event before confirming the result.",
            }
          : {
              kind: "success",
              title: "Disconnect requested",
              description: "The Pi accepted the scoped request. Waiting for Cowrie to confirm session closure.",
            },
      );
    } catch (error) {
      setTerminateError(error instanceof Error ? error.message : "Terminate request failed");
    } finally {
      setTerminateProcessing(false);
    }
  }, [selectedSession]);

  return {
    terminateCapability,
    terminateAction,
    visibleTerminateAction,
    visibleTerminateCapability,
    terminateDialogOpen,
    setTerminateDialogOpen,
    terminateProcessing,
    terminateError,
    setTerminateError,
    operationToast,
    setOperationToast,
    handleTerminateSession,
    fetchTerminateState,
  };
}
