"use client";

import { CheckCircle2, Power } from "lucide-react";
import type { FilesystemTopologySession, SessionTerminateAction } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { OperationToast } from "@/components/ui/OperationToast";
import type { OperationToastKind, TerminateCapability } from "./responseActionTypes";

export interface ResponseActionPanelProps {
  selectedSession: FilesystemTopologySession | null;
  sessionIsLive: boolean;
  visibleTerminateAction: SessionTerminateAction | null;
  visibleTerminateCapability: TerminateCapability;
  terminateDialogOpen: boolean;
  onTerminateDialogOpenChange: (open: boolean) => void;
  terminateProcessing: boolean;
  terminateError: string | undefined;
  onTerminateErrorChange: (error: string | undefined) => void;
  operationToast: { kind: OperationToastKind; title: string; description: string } | null;
  onOperationToastChange: (toast: { kind: OperationToastKind; title: string; description: string } | null) => void;
  onTerminateSession: () => Promise<void>;
}

/**
 * Pure response-action presentation. Fetching, polling, aborting, and terminal
 * feedback state are owned by useResponseActionController.
 */
export function ResponseActionPanel({
  selectedSession,
  sessionIsLive,
  visibleTerminateAction,
  visibleTerminateCapability,
  terminateDialogOpen,
  onTerminateDialogOpenChange,
  terminateProcessing,
  terminateError,
  onTerminateErrorChange,
  operationToast,
  onOperationToastChange,
  onTerminateSession,
}: ResponseActionPanelProps) {
  return (
    <>
      <div className="rounded-xl border border-border bg-surface-subtle p-3 space-y-2.5">
        <div className="text-xs font-semibold text-text">Selected session</div>
        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
          <div className="rounded bg-surface p-2 border border-border">
            <div className="text-xs text-text-subtle">Source IP</div>
            <div className="font-semibold text-text mt-0.5 truncate">{selectedSession?.sourceIp ?? "Unknown"}</div>
          </div>
          <div className="rounded bg-surface p-2 border border-border">
            <div className="text-xs text-text-subtle">Session ID</div>
            <div className="font-bold text-text mt-0.5 truncate">{selectedSession?.sessionId.slice(0, 10) ?? "Unknown"}…</div>
          </div>
        </div>
      </div>

      {visibleTerminateAction && (
        <div
          className="rounded-xl border border-border bg-surface-subtle p-3"
          aria-live="polite"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-text">Termination status</span>
            <span
              className={`inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 font-sans text-xs font-semibold ${
                visibleTerminateAction.status === "verified"
                  ? "border-success-border bg-success-subtle text-success"
                  : visibleTerminateAction.status === "failed"
                    ? "border-danger-border bg-danger-subtle text-danger"
                    : "border-warning-border bg-warning-subtle text-warning"
              }`}
            >
              {visibleTerminateAction.status === "verified" ? (
                <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
              ) : (
                <Power className="h-3 w-3" aria-hidden="true" />
              )}
              {visibleTerminateAction.status === "verified"
                ? "Verified"
                : visibleTerminateAction.status === "failed"
                  ? "Failed"
                  : visibleTerminateAction.status === "requested"
                    ? "Requested"
                    : "In progress"}
            </span>
          </div>
          <p className="mt-2 text-xs leading-5 text-text-muted">
            {visibleTerminateAction.status === "verified"
              ? "Cowrie confirmed that this exact transport closed."
              : visibleTerminateAction.status === "failed"
                ? `No verified closure${visibleTerminateAction.failureCategory ? ` (${visibleTerminateAction.failureCategory.replaceAll("_", " ")})` : ""}.`
                : visibleTerminateAction.status === "requested"
                  ? "The transport changed state during delivery; awaiting authoritative lifecycle confirmation."
                  : "Request delivered to the Pi; awaiting the session-closed event."}
          </p>
        </div>
      )}

      {visibleTerminateCapability === "loading" ? (
        <RegionState kind="loading" title="Checking response channel" />
      ) : visibleTerminateCapability === "forbidden" ? (
        <RegionState kind="empty" title="Admin access required" description="Only an Admin operator can disconnect a live Cowrie session." />
      ) : visibleTerminateCapability === "unconfigured" ? (
        <RegionState kind="empty" title="Response channel not configured" description="Configure the dashboard-to-Pi response agent before operational controls become available." />
      ) : visibleTerminateCapability === "error" ? (
        <RegionState kind="error" title="Response channel unavailable" description="The control capability could not be verified. No request was sent." />
      ) : !sessionIsLive ? (
        <RegionState kind="empty" title="Session already closed" description="Response actions are disabled for retained audit sessions." />
      ) : visibleTerminateAction && ["requested", "delivered", "verified"].includes(visibleTerminateAction.status) ? (
        <RegionState kind="empty" title="No response required" description="No further response actions are available for this session at this time." />
      ) : (
        <div className="rounded-xl border border-danger-border bg-danger-subtle p-3">
          <div className="flex items-start gap-2.5">
            <Power className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-xs font-semibold text-text">Disconnect this Cowrie session</p>
              <p className="mt-1 text-xs leading-5 text-text-muted">
                Closes only transport <span className="font-mono text-text">{selectedSession?.sessionId}</span>. It does not block the source IP or run a shell command.
              </p>
            </div>
          </div>
          <button
            type="button"
            className="ui-button ui-button-danger mt-3 w-full"
            onClick={() => {
              onTerminateErrorChange(undefined);
              onTerminateDialogOpenChange(true);
            }}
          >
            <Power className="h-4 w-4" aria-hidden="true" />
            Disconnect session
          </button>
        </div>
      )}

      <ConfirmDialog
        open={terminateDialogOpen}
        onOpenChange={onTerminateDialogOpenChange}
        onConfirm={onTerminateSession}
        title="Disconnect this live Cowrie session?"
        description={`This immediately closes session ${selectedSession?.sessionId ?? ""} from ${selectedSession?.sourceIp ?? "the selected source"}. The source IP is not blocked and Cowrie remains online.`}
        confirmLabel="Disconnect session"
        confirmVariant="danger"
        isProcessing={terminateProcessing}
        processingLabel="Sending request…"
        errorMessage={terminateError}
      />
      {operationToast && <OperationToast {...operationToast} onDismiss={() => onOperationToastChange(null)} />}
    </>
  );
}
