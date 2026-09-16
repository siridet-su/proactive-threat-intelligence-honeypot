import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";

export type HopResolutionStatus = "idle" | "resolving" | "resolved" | "not-found" | "error";

export interface SessionCwdHopPayload {
  item: SessionCwdHistoryEvent | null;
  hopNumber?: number;
  successfulHopNumber?: number;
  totalItems?: number;
  error?: string;
}

export interface SessionHopResolverOptions {
  sessionId: string;
  hopId: string;
  fetchHop?: (sessionId: string, hopId: string, signal: AbortSignal) => Promise<SessionCwdHopPayload>;
  onStatusChange?: (status: HopResolutionStatus) => void;
  onResolved?: (event: SessionCwdHistoryEvent) => void;
}

async function defaultFetchHop(
  sessionId: string,
  hopId: string,
  signal: AbortSignal,
): Promise<SessionCwdHopPayload> {
  const res = await fetch(
    `/api/sessions/${encodeURIComponent(sessionId)}/cwd-history?hop=${encodeURIComponent(hopId)}`,
    { cache: "no-store", signal },
  );
  if (res.status === 404) {
    return { item: null };
  }
  if (!res.ok) {
    throw new Error(`Hop request failed with status ${res.status}`);
  }
  return (await res.json()) as SessionCwdHopPayload;
}

export function mergeResolvedHistoryEvent(
  history: readonly SessionCwdHistoryEvent[],
  resolvedEvent: SessionCwdHistoryEvent,
): SessionCwdHistoryEvent[] {
  // If already present, don't duplicate
  if (history.some((e) => e.id === resolvedEvent.id)) {
    return [...history];
  }

  const combined = [...history, resolvedEvent];
  // Sort deterministic newest-first: at descending, id descending
  combined.sort((a, b) => {
    const timeA = Date.parse(a.at);
    const timeB = Date.parse(b.at);
    if (!Number.isNaN(timeA) && !Number.isNaN(timeB) && timeA !== timeB) {
      return timeB - timeA;
    }
    return b.id.localeCompare(a.id);
  });
  return combined;
}

export class SessionHopResolver {
  private sessionId: string;
  private hopId: string;
  private status: HopResolutionStatus = "idle";
  private fetchHop: (sessionId: string, hopId: string, signal: AbortSignal) => Promise<SessionCwdHopPayload>;
  private onStatusChange?: (status: HopResolutionStatus) => void;
  private onResolved?: (event: SessionCwdHistoryEvent) => void;
  private abortController: AbortController | null = null;
  private resolvedEvent: SessionCwdHistoryEvent | null = null;

  constructor(options: SessionHopResolverOptions) {
    this.sessionId = options.sessionId;
    this.hopId = options.hopId;
    this.fetchHop = options.fetchHop ?? defaultFetchHop;
    this.onStatusChange = options.onStatusChange;
    this.onResolved = options.onResolved;
  }

  getStatus(): HopResolutionStatus {
    return this.status;
  }

  getHopId(): string {
    return this.hopId;
  }

  getSessionId(): string {
    return this.sessionId;
  }

  getResolvedEvent(): SessionCwdHistoryEvent | null {
    return this.resolvedEvent;
  }

  private setStatus(status: HopResolutionStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.onStatusChange?.(status);
  }

  /**
   * Checks whether the target hop is present in the provided history items.
   * If found, immediately resolves without network work.
   */
  checkPageItems(items: readonly SessionCwdHistoryEvent[]): boolean {
    const match = items.find((item) => item.id === this.hopId);
    if (match) {
      this.resolvedEvent = match;
      this.setStatus("resolved");
      this.onResolved?.(match);
      return true;
    }
    return false;
  }

  /**
   * Performs direct indexed lookup for (sessionId, hopId).
   */
  async resolveDirect(): Promise<SessionCwdHistoryEvent | null> {
    if (this.status === "resolved" && this.resolvedEvent) {
      return this.resolvedEvent;
    }
    this.abort();
    this.setStatus("resolving");

    const controller = new AbortController();
    this.abortController = controller;

    try {
      const payload = await this.fetchHop(this.sessionId, this.hopId, controller.signal);
      if (controller.signal.aborted) return null;

      if (payload.item) {
        // Enforce session boundary: never resolve an event belonging to another session
        if (payload.item.sessionId !== this.sessionId) {
          this.setStatus("not-found");
          return null;
        }

        if (typeof payload.hopNumber === "number") {
          payload.item.hopNumber = payload.hopNumber;
        }
        if (typeof payload.successfulHopNumber === "number") {
          payload.item.successfulHopNumber = payload.successfulHopNumber;
        }

        this.resolvedEvent = payload.item;
        this.setStatus("resolved");
        this.onResolved?.(payload.item);
        return payload.item;
      }

      this.setStatus("not-found");
      return null;
    } catch {
      if (controller.signal.aborted) return null;
      this.setStatus("error");
      return null;
    } finally {
      if (this.abortController === controller) {
        this.abortController = null;
      }
    }
  }

  abort(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }
}

export interface SessionHopLifecycleSyncParams {
  sessionId: string | null;
  hopId: string | null;
  viewMode?: "live" | "audit";
  history: readonly SessionCwdHistoryEvent[];
  fetchHop?: (sessionId: string, hopId: string, signal: AbortSignal) => Promise<SessionCwdHopPayload>;
  onStatusChange: (status: HopResolutionStatus) => void;
  onResolved: (event: SessionCwdHistoryEvent) => void;
}

export class SessionHopLifecycleManager {
  private activeSessionId: string | null = null;
  private activeHopId: string | null = null;
  private activeResolver: SessionHopResolver | null = null;
  private generation = 0;

  sync(params: SessionHopLifecycleSyncParams): void {
    const isAudit = params.viewMode === undefined || params.viewMode === "audit";
    const shouldResolve = Boolean(isAudit && params.sessionId && params.hopId);

    if (!shouldResolve || !params.sessionId || !params.hopId) {
      this.abort();
      this.activeSessionId = null;
      this.activeHopId = null;
      params.onStatusChange("idle");
      return;
    }

    const isSameIdentity =
      this.activeSessionId === params.sessionId &&
      this.activeHopId === params.hopId &&
      this.activeResolver !== null;

    if (isSameIdentity) {
      // Check if page items now include the hop
      if (this.activeResolver!.getStatus() === "resolving" || this.activeResolver!.getStatus() === "idle") {
        if (this.activeResolver!.checkPageItems(params.history)) {
          return;
        }
      }
      return;
    }

    // New resolution scope
    this.abort();
    this.generation += 1;
    const currentGen = this.generation;
    const currentSessionId = params.sessionId;
    const currentHopId = params.hopId;

    this.activeSessionId = currentSessionId;
    this.activeHopId = currentHopId;

    const resolver = new SessionHopResolver({
      sessionId: currentSessionId,
      hopId: currentHopId,
      fetchHop: params.fetchHop,
      onStatusChange: (status) => {
        if (this.generation !== currentGen || this.activeSessionId !== currentSessionId) return;
        params.onStatusChange(status);
      },
      onResolved: (event) => {
        if (this.generation !== currentGen || this.activeSessionId !== currentSessionId) return;
        params.onResolved(event);
      },
    });

    this.activeResolver = resolver;

    // First check if already in loaded history items
    if (resolver.checkPageItems(params.history)) {
      return;
    }

    // Otherwise initiate direct server lookup
    void resolver.resolveDirect();
  }

  abort(): void {
    if (this.activeResolver) {
      this.activeResolver.abort();
      this.activeResolver = null;
    }
  }

  destroy(): void {
    this.abort();
    this.activeSessionId = null;
    this.activeHopId = null;
  }

  getActiveResolver(): SessionHopResolver | null {
    return this.activeResolver;
  }
}
