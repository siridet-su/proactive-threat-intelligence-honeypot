import type { SessionTerminateAction } from "@/lib/dashboardTypes";
import type { OperationToastKind } from "@/components/ui/OperationToast";

export type TerminateCapability = "idle" | "loading" | "available" | "forbidden" | "unconfigured" | "error";
export type { OperationToastKind };

export interface TerminateStatePayload {
  available?: boolean;
  authorized?: boolean;
  configured?: boolean;
  action?: SessionTerminateAction | null;
}

export function terminateCapabilityFrom(
  document: TerminateStatePayload,
  previousCapability?: TerminateCapability,
): TerminateCapability {
  if (document.available === true) return "available";
  if (!document.authorized) return "forbidden";
  if (!document.configured) return "unconfigured";
  if (document.available === false) return "error";
  // When document.available is undefined (status-only response where health was not probed),
  // preserve the previous authoritative capability if provided, or default to "available".
  return previousCapability ?? "available";
}
