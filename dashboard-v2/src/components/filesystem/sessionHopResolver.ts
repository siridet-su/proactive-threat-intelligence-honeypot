import type {
  AuditSessionsPage,
  FilesystemClosedSession,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";

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
  retryOnError?: boolean;
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
      const resolver = this.activeResolver!;
      const currentStatus = resolver.getStatus();

      // Check if newly loaded history items now include the hop
      if (currentStatus === "resolving" || currentStatus === "idle") {
        if (resolver.checkPageItems(params.history)) {
          return;
        }
      }

      // Authoritative re-emission: always re-emit state for the same identity on refresh
      params.onStatusChange(currentStatus);

      if (currentStatus === "resolved") {
        const resolvedEvent = resolver.getResolvedEvent();
        if (resolvedEvent) {
          params.onResolved(resolvedEvent);
        }
      } else if (currentStatus === "error" && params.retryOnError) {
        // Errors retry only on explicit retry action
        void resolver.resolveDirect();
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

export interface RemoteAuditLookupIntent {
  sessionId: string;
  targetHopId?: string | null;
}

export interface RemoteAuditLookupCallback {
  onSessionFound: (session: FilesystemClosedSession, targetHopId?: string | null) => void;
  onSessionNotFound: (sessionId: string) => void;
}

export type RemoteAuditLookupCallbacks = RemoteAuditLookupCallback;

export interface RemoteAuditLookupCoordinatorOptions {
  initialViewMode?: "live" | "audit";
  initialSessionId?: string | null;
  fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>;
  callbacks?: RemoteAuditLookupCallback;
}

export class RemoteAuditLookupCoordinator {
  private viewMode: "live" | "audit";
  private currentSessionId: string | null = null;
  private inFlightIntent: {
    sessionId: string;
    targetHopId?: string | null;
    generation: number;
  } | null = null;
  private generation = 0;
  private abortController: AbortController | null = null;
  private fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>;
  private callbacks?: RemoteAuditLookupCallback;

  constructor(options?: RemoteAuditLookupCoordinatorOptions) {
    this.viewMode = options?.initialViewMode ?? "live";
    this.currentSessionId = options?.initialSessionId ?? null;
    this.fetchSession = options?.fetchSession;
    this.callbacks = options?.callbacks;
  }

  setCallbacks(callbacks: RemoteAuditLookupCallback): void {
    this.callbacks = callbacks;
  }

  getViewMode(): "live" | "audit" {
    return this.viewMode;
  }

  getCurrentSessionId(): string | null {
    return this.currentSessionId;
  }

  getInFlightSessionId(): string | null {
    return this.inFlightIntent?.sessionId ?? null;
  }

  getInFlightIntent(): RemoteAuditLookupIntent | null {
    if (!this.inFlightIntent) return null;
    return {
      sessionId: this.inFlightIntent.sessionId,
      targetHopId: this.inFlightIntent.targetHopId,
    };
  }

  getGeneration(): number {
    return this.generation;
  }

  /**
   * Notifies the coordinator that viewMode has changed (Live/Audit switch or popstate).
   * Switching out of audit mode invalidates any in-flight remote lookup.
   */
  notifyViewModeChanged(nextMode: "live" | "audit"): void {
    if (this.viewMode === nextMode) return;
    this.viewMode = nextMode;
    if (nextMode !== "audit") {
      this.abort();
    }
  }

  /**
   * Notifies the coordinator that a session was selected (user click, topology click,
   * popstate to known session, etc.). If an in-flight lookup exists for a different
   * session, it is immediately aborted.
   */
  notifySessionSelected(sessionId: string | null): void {
    this.currentSessionId = sessionId;
    if (this.inFlightIntent && this.inFlightIntent.sessionId !== sessionId) {
      this.abort();
    }
  }

  /**
   * Requests a remote lookup for a retained session not in the active snapshot.
   *
   * Idempotence & Deduplication:
   * Repeated snapshot updates for the same in-flight {sessionId, targetHopId}
   * reuse the existing lookup without aborting or restarting it.
   *
   * Scope change:
   * A genuinely different remote intent aborts the old request and starts a new one.
   */
  async requestLookup(
    intent: RemoteAuditLookupIntent,
    overrideCallbacks?: RemoteAuditLookupCallback,
    overrideFetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>,
  ): Promise<FilesystemClosedSession | null> {
    const { sessionId, targetHopId } = intent;
    if (!sessionId) return null;

    if (this.viewMode !== "audit") {
      return null;
    }

    const callbacks = overrideCallbacks ?? this.callbacks;
    const fetchFn = overrideFetchSession ?? this.fetchSession;

    // Reuse in-flight lookup if same intent is already executing
    if (
      this.inFlightIntent &&
      this.inFlightIntent.sessionId === sessionId &&
      (this.inFlightIntent.targetHopId ?? null) === (targetHopId ?? null)
    ) {
      return null;
    }

    // A genuinely different intent aborts the old request
    this.abort();
    this.generation += 1;
    const currentGen = this.generation;

    this.inFlightIntent = {
      sessionId,
      targetHopId,
      generation: currentGen,
    };

    const controller = new AbortController();
    this.abortController = controller;

    try {
      let found: FilesystemClosedSession | null = null;
      if (fetchFn) {
        found = await fetchFn(sessionId, controller.signal);
      } else {
        const res = await fetch(
          `/api/filesystem-topology/audit-sessions?search=${encodeURIComponent(sessionId)}&limit=1`,
          { cache: "no-store", signal: controller.signal },
        );
        if (res.ok) {
          const data: unknown = await res.json();
          const page = data as Partial<AuditSessionsPage>;
          found = page.items?.find((s) => s.sessionId === sessionId) ?? null;
        }
      }

      // Check if navigation scope or generation moved while awaiting response
      if (
        controller.signal.aborted ||
        this.generation !== currentGen ||
        this.viewMode !== "audit" ||
        !this.inFlightIntent ||
        this.inFlightIntent.generation !== currentGen ||
        this.inFlightIntent.sessionId !== sessionId
      ) {
        return null;
      }

      if (found) {
        callbacks?.onSessionFound(found, targetHopId);
        return found;
      } else {
        callbacks?.onSessionNotFound(sessionId);
        return null;
      }
    } catch {
      if (
        controller.signal.aborted ||
        this.generation !== currentGen ||
        this.viewMode !== "audit" ||
        !this.inFlightIntent ||
        this.inFlightIntent.generation !== currentGen
      ) {
        return null;
      }
      callbacks?.onSessionNotFound(sessionId);
      return null;
    } finally {
      if (this.generation === currentGen) {
        this.inFlightIntent = null;
        this.abortController = null;
      }
    }
  }

  /**
   * Backwards-compatible alias for requestLookup.
   */
  async lookup(
    intent: RemoteAuditLookupIntent,
    callbacks: RemoteAuditLookupCallback,
    fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>,
  ): Promise<FilesystemClosedSession | null> {
    return this.requestLookup(intent, callbacks, fetchSession);
  }

  abort(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    this.inFlightIntent = null;
    this.generation += 1;
  }

  destroy(): void {
    this.abort();
    this.currentSessionId = null;
    this.callbacks = undefined;
  }
}

export { RemoteAuditLookupCoordinator as RemoteAuditLookupManager };
