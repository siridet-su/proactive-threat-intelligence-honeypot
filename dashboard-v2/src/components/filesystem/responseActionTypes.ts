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

export function terminateCapabilityFrom(document: TerminateStatePayload): TerminateCapability {
  return document.available ? "available" : !document.authorized ? "forbidden" : !document.configured ? "unconfigured" : "error";
}
