"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { FilesystemTopologySession, SessionTerminateAction } from "@/lib/dashboardTypes";
import type { OperationToastKind } from "@/components/ui/OperationToast";
import { ResponseActionPollingController } from "./responseActionPoller";

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

  const actionId = visibleTerminateAction?.actionId ?? null;
  const actionStatus = visibleTerminateAction?.status ?? null;
  const shouldPoll = Boolean(
    enabled &&
    controlSessionId &&
    actionId &&
    (actionStatus === "requested" || actionStatus === "delivered")
  );

  const pollerRef = useRef<ResponseActionPollingController | null>(null);

  // Bounded single-lifecycle polling per action
  useEffect(() => {
    if (!shouldPoll || !controlSessionId || !actionId) {
      if (pollerRef.current) {
        pollerRef.current.abort();
        pollerRef.current = null;
      }
      return;
    }

    // Do not restart polling if the controller for this exact session and action is already active
    if (pollerRef.current?.matches(controlSessionId, actionId)) {
      return;
    }

    if (pollerRef.current) {
      pollerRef.current.abort();
      pollerRef.current = null;
    }

    const poller = new ResponseActionPollingController({
      sessionId: controlSessionId,
      actionId,
      requestedAt: visibleTerminateAction?.requestedAt,
      sessionIsLive,
      fetchState: fetchTerminateState,
      onActionUpdate: (action, capability) => {
        setTerminateAction(action);
        setTerminateCapability(capability);
        setTerminateCapabilitySessionId(controlSessionId);
      },
      onTerminal: (event) => {
        if (event.kind === "verified") {
          setOperationToast({
            kind: "success",
            title: "Session disconnected",
            description: "Cowrie emitted the verified session-closed lifecycle event.",
          });
        } else if (event.kind === "failed") {
          const description = event.failureCategory
            ? `Action failed: ${event.failureCategory.replace(/_/g, " ")}`
            : "Session termination could not be verified.";
          setOperationToast({
            kind: "error",
            title: "Disconnection failed",
            description,
          });
        } else if (event.kind === "timeout") {
          setOperationToast({
            kind: "error",
            title: "Disconnection timed out",
            description: "Session closure could not be verified within the expected window. State reconciliation may still be in progress.",
          });
        }
      },
    });

    pollerRef.current = poller;
    poller.start();

    return () => {
      poller.abort();
      if (pollerRef.current === poller) {
        pollerRef.current = null;
      }
    };
  }, [controlSessionId, actionId, shouldPoll, sessionIsLive, enabled, fetchTerminateState, visibleTerminateAction?.requestedAt]);

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
