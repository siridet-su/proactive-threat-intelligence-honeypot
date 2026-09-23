import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";

export type CwdTransitionPresentationKind =
  | "directed"
  | "entry"
  | "failed-origin"
  | "unavailable";

export type VerifiedCwdTransitionAction = "entered" | "changed" | "failed_change";

export interface VerifiedCwdTransition {
  eventId: string;
  absoluteHop: number | null;
  action: VerifiedCwdTransitionAction;
  presentationKind: CwdTransitionPresentationKind;
  fromPath: string | null;
  toPath: string | null;
  markerPath: string | null;
  observedAt: string;
  status: SessionCwdHistoryEvent["status"];
}

function verifiedAbsolutePath(path: string | null | undefined): string | null {
  if (typeof path !== "string" || path.length === 0 || !path.startsWith("/")) return null;
  return path;
}

function safeAbsoluteHop(absoluteHop: number | null | undefined): number | null {
  return typeof absoluteHop === "number" && Number.isSafeInteger(absoluteHop) && absoluteHop > 0
    ? absoluteHop
    : null;
}

/**
 * Converts one authoritative CWD event into a presentation-safe transition.
 * Raw event destinations are intentionally never copied into failed or
 * unavailable presentation models.
 */
export function deriveVerifiedCwdTransition(
  event: SessionCwdHistoryEvent,
  absoluteHop: number | null | undefined,
): VerifiedCwdTransition {
  const safeHop = safeAbsoluteHop(absoluteHop);
  const base = {
    eventId: event.id,
    absoluteHop: safeHop,
    observedAt: event.at,
    status: event.status,
  };

  if (event.action === "failed_change") {
    const origin = verifiedAbsolutePath(event.fromPath);
    return {
      ...base,
      action: "failed_change",
      presentationKind: "failed-origin",
      fromPath: origin,
      toPath: null,
      markerPath: origin,
    };
  }

  if (event.action === "entered") {
    const target = verifiedAbsolutePath(event.toPath);
    return {
      ...base,
      action: "entered",
      presentationKind: target ? "entry" : "unavailable",
      fromPath: null,
      toPath: target,
      markerPath: target,
    };
  }

  const origin = verifiedAbsolutePath(event.fromPath);
  const target = verifiedAbsolutePath(event.toPath);
  if (!origin || !target) {
    return {
      ...base,
      action: "changed",
      presentationKind: "unavailable",
      fromPath: null,
      toPath: null,
      markerPath: null,
    };
  }

  return {
    ...base,
    action: "changed",
    presentationKind: "directed",
    fromPath: origin,
    toPath: target,
    markerPath: null,
  };
}

/**
 * Applies the authoritative retained-total bound to an event resolved outside
 * the loaded page, then delegates to the same single-event mapper used by the
 * loaded-window path.
 */
export function deriveAnchoredVerifiedCwdTransition(
  event: SessionCwdHistoryEvent,
  historyTotalItems: number | null | undefined,
): VerifiedCwdTransition {
  const hasSafeTotal = Number.isSafeInteger(historyTotalItems) && (historyTotalItems ?? -1) >= 0;
  const hopNumber = event.hopNumber;
  const hasSafeHop = typeof hopNumber === "number" && Number.isSafeInteger(hopNumber) && hopNumber > 0;
  const isWithinRetainedTotal = !hasSafeTotal || hopNumber! <= (historyTotalItems as number);
  const absoluteHop = hasSafeHop && isWithinRetainedTotal ? hopNumber : null;
  return deriveVerifiedCwdTransition(event, absoluteHop);
}

function safeHistoryTotal(loadedItems: number, historyTotalItems: number | null | undefined): number {
  if (!Number.isSafeInteger(historyTotalItems) || (historyTotalItems ?? -1) < 0) return loadedItems;
  return Math.max(loadedItems, historyTotalItems as number);
}

/**
 * Maps a loaded chronological history window without changing its order or
 * filtering any event. The offset is based on the complete retained count, so
 * failed events keep their absolute positions when a display filter hides
 * them later.
 */
export function deriveVerifiedCwdTransitions(
  events: readonly SessionCwdHistoryEvent[],
  historyTotalItems: number | null | undefined,
): VerifiedCwdTransition[] {
  const loadedItems = events.length;
  const totalItems = safeHistoryTotal(loadedItems, historyTotalItems);
  const indexOffset = totalItems - loadedItems;

  return events.map((event, index) => deriveVerifiedCwdTransition(event, indexOffset + index + 1));
}
