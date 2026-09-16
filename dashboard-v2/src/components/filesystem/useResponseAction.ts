"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { FilesystemTopologySession, SessionTerminateAction } from "@/lib/dashboardTypes";
import type { OperationToastKind, TerminateCapability, TerminateStatePayload } from "./responseActionTypes";
import { terminateCapabilityFrom } from "./responseActionTypes";
import { ResponseActionLifecycleManager } from "./responseActionPoller";

export type { TerminateCapability, OperationToastKind, TerminateStatePayload };
export { terminateCapabilityFrom };

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
  const managerRef = useRef<ResponseActionLifecycleManager | null>(null);

  // Keep single-lifecycle polling synchronized across renders and state changes
  useEffect(() => {
    if (!managerRef.current) {
      managerRef.current = new ResponseActionLifecycleManager();
    }
    managerRef.current.sync({
      sessionId: controlSessionId,
      actionId,
      actionStatus,
      sessionIsLive,
      requestedAt: visibleTerminateAction?.requestedAt,
      initialCapability: terminateCapability,
      initialAction: visibleTerminateAction ?? null,
      enabled,
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
  }, [controlSessionId, actionId, actionStatus, sessionIsLive, visibleTerminateAction, terminateCapability, enabled, fetchTerminateState]);

  // Clean up polling controller strictly upon unmount
  useEffect(() => {
    return () => {
      managerRef.current?.destroy();
    };
  }, []);

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
