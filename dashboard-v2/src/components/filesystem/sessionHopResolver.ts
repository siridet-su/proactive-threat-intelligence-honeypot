import type {
  AuditSessionsPage,
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";
import {
  resolveSessionSelection,
  type SessionResolutionResult,
} from "./filesystemUtils";

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

export type RemoteAuditLookupOutcome =
  | {
      type: "found";
      session: FilesystemClosedSession;
      targetHopId: string | null;
    }
  | {
      type: "not-found";
      sessionId: string;
      reason: "not-found" | "error";
    };

/**
 * A terminal observer can observe the result of a lookup, but is not eligible
 * to apply the authoritative session result. Instances must be created through
 * createRemoteAuditLookupTerminalObserver so runtime registration can reject
 * arbitrary mutation callbacks passed to the observer path.
 */
export interface RemoteAuditLookupTerminalObserver {
  onLookupCompleted: (outcome: RemoteAuditLookupOutcome) => void;
}

const registeredTerminalObservers = new WeakSet<object>();

export function createRemoteAuditLookupTerminalObserver(
  onLookupCompleted: (outcome: RemoteAuditLookupOutcome) => void,
): RemoteAuditLookupTerminalObserver {
  const observer: RemoteAuditLookupTerminalObserver = { onLookupCompleted };
  registeredTerminalObservers.add(observer);
  return observer;
}

function isRegisteredTerminalObserver(observer: object): boolean {
  return registeredTerminalObservers.has(observer);
}

export interface NavigationScope {
  viewMode: "live" | "audit";
  sessionId: string | null;
  targetHopId: string | null;
  generation: number;
}

export function normalizeHop(hop?: string | null): string | null {
  if (!hop) return null;
  const trimmed = hop.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export interface RemoteAuditLookupCoordinatorOptions {
  initialViewMode?: "live" | "audit";
  initialSessionId?: string | null;
  initialTargetHopId?: string | null;
  fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>;
  callbacks?: RemoteAuditLookupCallback;
}

export class RemoteAuditLookupCoordinator {
  private viewMode: "live" | "audit";
  private currentSessionId: string | null = null;
  private currentTargetHopId: string | null = null;
  private inFlightIntent: {
    sessionId: string;
    targetHopId: string | null;
    generation: number;
    promise: Promise<FilesystemClosedSession | null>;
    /** The authoritative callback that performs domain mutations exactly once. */
    mutationOwner: RemoteAuditLookupCallback | undefined;
    /** Terminal-only observers notified after the mutation owner commits. */
    terminalObservers: Set<RemoteAuditLookupTerminalObserver>;
  } | null = null;
  private generation = 0;
  private abortController: AbortController | null = null;
  private fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>;
  private callbacks?: RemoteAuditLookupCallback;

  constructor(options?: RemoteAuditLookupCoordinatorOptions) {
    this.viewMode = options?.initialViewMode ?? "live";
    this.currentSessionId = options?.initialSessionId ?? null;
    this.currentTargetHopId = normalizeHop(options?.initialTargetHopId);
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

  getCurrentTargetHopId(): string | null {
    return this.currentTargetHopId;
  }

  getNavigationScope(): NavigationScope {
    return {
      viewMode: this.viewMode,
      sessionId: this.currentSessionId,
      targetHopId: this.currentTargetHopId,
      generation: this.generation,
    };
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
   * Authoritative navigation scope update.
   * Any explicit navigation changing session or hop:
   * - same session, different hop
   * - same session, hop cleared
   * - popstate to known session with different hop/null
   * - user selection of current session (explicitly clears hop)
   * - switching to live
   *
   * advances generation and invalidates/aborts the prior lookup,
   * while preserving deduplication for repeated identical requests.
   */
  notifyNavigationScope(scope: {
    viewMode?: "live" | "audit";
    sessionId?: string | null;
    targetHopId?: string | null;
  }): void {
    const nextViewMode = scope.viewMode !== undefined ? scope.viewMode : this.viewMode;
    const nextSessionId = scope.sessionId !== undefined ? (scope.sessionId ?? null) : this.currentSessionId;
    let nextTargetHopId = scope.targetHopId !== undefined ? normalizeHop(scope.targetHopId) : this.currentTargetHopId;
    if (nextViewMode === "live") {
      nextTargetHopId = null;
    }

    const isSameScope =
      this.viewMode === nextViewMode &&
      this.currentSessionId === nextSessionId &&
      this.currentTargetHopId === nextTargetHopId;

    const matchesInFlight =
      !this.inFlightIntent ||
      (this.inFlightIntent.sessionId === nextSessionId &&
        normalizeHop(this.inFlightIntent.targetHopId) === nextTargetHopId &&
        nextViewMode === "audit");

    if (isSameScope && matchesInFlight) {
      return;
    }

    this.viewMode = nextViewMode;
    this.currentSessionId = nextSessionId;
    this.currentTargetHopId = nextTargetHopId;

    this.abort();
  }

  /**
   * Notifies the coordinator that viewMode has changed (Live/Audit switch or popstate).
   */
  notifyViewModeChanged(nextMode: "live" | "audit"): void {
    this.notifyNavigationScope({ viewMode: nextMode });
  }

  /**
   * Notifies the coordinator that a session was selected.
   * Defaults targetHopId to null (hop cleared on session change/user click).
   */
  notifySessionSelected(sessionId: string | null, targetHopId: string | null = null): void {
    this.notifyNavigationScope({
      sessionId,
      targetHopId,
    });
  }

  /**
   * Adopts a locally authoritative session scope (e.g. from snapshot or local selection).
   * Enforces the invariant:
   * - Live mode always forces targetHopId to null.
   * - Audit mode preserves the normalized targetHopId.
   * Updates navigation scope and cancels any active in-flight lookup.
   */
  adoptLocalSessionScope(
    sessionId: string,
    targetHopId?: string | null,
    viewMode?: "live" | "audit",
  ): string | null {
    if (viewMode !== undefined) {
      this.viewMode = viewMode;
    }
    const effectiveHop = this.viewMode === "live" ? null : normalizeHop(targetHopId);
    this.currentSessionId = sessionId;
    this.currentTargetHopId = effectiveHop;

    if (this.inFlightIntent) {
      this.abort();
    }
    return effectiveHop;
  }

  /**
   * Notifies the coordinator that a session has become authoritative locally
   * (e.g. found in snapshot.sessions, snapshot.recentClosedSessions, or authoritative directory).
   *
   * Backwards-compatible alias for adoptLocalSessionScope.
   */
  notifySessionResolvedLocally(
    sessionId: string,
    targetHopId?: string | null,
    viewMode?: "live" | "audit",
  ): void {
    this.adoptLocalSessionScope(sessionId, targetHopId, viewMode);
  }

  /**
   * Requests a remote lookup for a retained session not in the active snapshot.
   *
   * Ownership model:
   * The first caller becomes the authoritative "mutation owner" whose callbacks
   * perform domain-state mutations (setExtraAuditSessions, selectSession, etc.)
   * exactly once. Subsequent callers with the same in-flight intent are added as
   * "join observers" that receive the outcome notification after the owner commits,
   * enabling them to perform lightweight terminal-state updates (e.g. marking a
   * popstate transaction terminal) without repeating any domain mutation.
   *
   * Idempotence & Deduplication:
   * Repeated calls for the same in-flight {sessionId, targetHopId} reuse the
   * existing in-flight promise without aborting, restarting, or returning premature
   * null. The SAME promise object is returned to all callers preserving reference
   * identity so callers can distinguish joins via toBe().
   *
   * Synchronous-exception safety:
   * The in-flight record is installed before invoking fetchFn. A synchronous throw
   * in fetchFn settles through the catch path, clears inFlightIntent in finally,
   * and leaves isInFlight() false — allowing a clean retry with a new request.
   *
   * Scope change:
   * A genuinely different remote intent aborts the old request, clears observers,
   * and starts a new one.
   */
  requestLookup(
    intent: RemoteAuditLookupIntent,
    overrideCallbacks?: RemoteAuditLookupCallback,
    overrideFetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>,
  ): Promise<FilesystemClosedSession | null> {
    const sessionId = intent.sessionId;
    const normHop = normalizeHop(intent.targetHopId);
    if (!sessionId) return Promise.resolve(null);

    if (this.viewMode !== "audit") {
      return Promise.resolve(null);
    }

    const callbacks = overrideCallbacks ?? this.callbacks;
    const fetchFn = overrideFetchSession ?? this.fetchSession;

    // Repeated owner requests for the same intent return the SAME promise object.
    // A callback already registered as the owner is never registered again. A
    // different RemoteAuditLookupCallback is intentionally ignored here: it is
    // not a terminal observer and must not enter the observer collection.
    if (
      this.inFlightIntent &&
      this.inFlightIntent.sessionId === sessionId &&
      normalizeHop(this.inFlightIntent.targetHopId) === normHop
    ) {
      return this.inFlightIntent.promise;
    }

    // A genuinely different intent aborts the old request
    this.abort();
    this.currentSessionId = sessionId;
    this.currentTargetHopId = normHop;
    const currentGen = this.generation;

    const controller = new AbortController();
    this.abortController = controller;

    // Construct the real shared promise before invoking any external code.
    // This is important for a synchronous/reentrant fetchFn: a nested request
    // must observe this exact promise rather than a temporary null placeholder.
    let resolveShared!: (value: FilesystemClosedSession | null) => void;
    let rejectShared!: (reason?: unknown) => void;
    const sharedPromise = new Promise<FilesystemClosedSession | null>((resolve, reject) => {
      resolveShared = resolve;
      rejectShared = reject;
    });

    const terminalObservers = new Set<RemoteAuditLookupTerminalObserver>();
    const inFlightRecord: {
      sessionId: string;
      targetHopId: string | null;
      generation: number;
      promise: Promise<FilesystemClosedSession | null>;
      mutationOwner: RemoteAuditLookupCallback | undefined;
      terminalObservers: Set<RemoteAuditLookupTerminalObserver>;
    } = {
      sessionId,
      targetHopId: normHop,
      generation: currentGen,
      promise: sharedPromise,
      mutationOwner: callbacks ?? undefined,
      terminalObservers,
    };
    this.inFlightIntent = inFlightRecord;

    const performLookup = async (): Promise<FilesystemClosedSession | null> => {
      try {
        let found: FilesystemClosedSession | null = null;
        let outcomeReason: "not-found" | "error" = "not-found";
        if (fetchFn) {
          try {
            found = await fetchFn(sessionId, controller.signal);
          } catch {
            outcomeReason = "error";
          }
        } else {
          try {
            const res = await fetch(
              `/api/filesystem-topology/audit-sessions?search=${encodeURIComponent(sessionId)}&limit=1`,
              { cache: "no-store", signal: controller.signal },
            );
            if (res.ok) {
              const data: unknown = await res.json();
              const page = data as Partial<AuditSessionsPage>;
              found = page.items?.find((s) => s.sessionId === sessionId) ?? null;
            }
          } catch {
            outcomeReason = "error";
          }
        }

        // Check if navigation scope or generation moved while awaiting response
        if (!this.isCurrentLookup(inFlightRecord, controller, sessionId, normHop, currentGen)) {
          return null;
        }

        // Snapshot terminal observers before owner application. The owner may
        // synchronously adopt local state and abort/clear this lookup.
        const owner = inFlightRecord.mutationOwner;
        const observers = Array.from(terminalObservers);
        terminalObservers.clear();

        if (found) {
          if (owner) {
            owner.onSessionFound(found, normHop);
          }
          const outcome: RemoteAuditLookupOutcome = {
            type: "found",
            session: found,
            targetHopId: normHop,
          };
          this.notifyTerminalObservers(observers, outcome);
          return found;
        } else {
          if (owner) {
            owner.onSessionNotFound(sessionId);
          }
          const outcome: RemoteAuditLookupOutcome = {
            type: "not-found",
            sessionId,
            reason: outcomeReason,
          };
          this.notifyTerminalObservers(observers, outcome);
          return null;
        }
      } finally {
        if (this.inFlightIntent === inFlightRecord) {
          this.inFlightIntent = null;
          if (this.abortController === controller) {
            this.abortController = null;
          }
        }
      }
    };

    // The record already contains the real promise. Starting the worker may
    // synchronously invoke fetchFn, including reentrant requestLookup calls.
    void performLookup().then(resolveShared, rejectShared);

    return sharedPromise;
  }

  private isCurrentLookup(
    record: {
      sessionId: string;
      targetHopId: string | null;
      generation: number;
      promise: Promise<FilesystemClosedSession | null>;
      mutationOwner: RemoteAuditLookupCallback | undefined;
      terminalObservers: Set<RemoteAuditLookupTerminalObserver>;
    },
    controller: AbortController,
    sessionId: string,
    targetHopId: string | null,
    generation: number,
  ): boolean {
    return (
      !controller.signal.aborted &&
      this.generation === generation &&
      this.viewMode === "audit" &&
      this.inFlightIntent === record &&
      record.generation === generation &&
      record.sessionId === sessionId &&
      normalizeHop(record.targetHopId) === targetHopId &&
      this.currentSessionId === sessionId &&
      normalizeHop(this.currentTargetHopId) === targetHopId
    );
  }

  private notifyTerminalObservers(
    observers: RemoteAuditLookupTerminalObserver[],
    outcome: RemoteAuditLookupOutcome,
  ): void {
    for (const observer of observers) {
      try {
        observer.onLookupCompleted(outcome);
      } catch {
        // A terminal observer is not authoritative; its failure must not
        // change the shared lookup result or the owner's committed state.
      }
    }
  }

  /**
   * Joins an exact in-flight intent as a terminal-only observer. This method
   * cannot promote the observer to the mutation owner and rejects unregistered
   * arbitrary callback objects at runtime.
   */
  joinLookup(
    intent: RemoteAuditLookupIntent,
    observer: RemoteAuditLookupTerminalObserver,
  ): Promise<FilesystemClosedSession | null> {
    if (!isRegisteredTerminalObserver(observer)) {
      throw new TypeError("joinLookup requires a registered terminal observer");
    }

    const sessionId = intent.sessionId;
    const normHop = normalizeHop(intent.targetHopId);
    const active = this.inFlightIntent;
    if (
      !sessionId ||
      this.viewMode !== "audit" ||
      !active ||
      active.sessionId !== sessionId ||
      normalizeHop(active.targetHopId) !== normHop
    ) {
      throw new Error("Cannot join a different or inactive remote lookup intent");
    }

    active.terminalObservers.add(observer);
    return active.promise;
  }

  /** Backwards-compatible alias for joinLookup. */
  join(
    intent: RemoteAuditLookupIntent,
    observer: RemoteAuditLookupTerminalObserver,
  ): Promise<FilesystemClosedSession | null> {
    return this.joinLookup(intent, observer);
  }

  /**
   * Returns true if a remote lookup is currently in flight.
   */
  isInFlight(): boolean {
    return this.inFlightIntent !== null;
  }

  /**
   * Backwards-compatible alias for requestLookup.
   */
  lookup(
    intent: RemoteAuditLookupIntent,
    callbacks?: RemoteAuditLookupCallback,
    fetchSession?: (sessionId: string, signal: AbortSignal) => Promise<FilesystemClosedSession | null>,
  ): Promise<FilesystemClosedSession | null> {
    return this.requestLookup(intent, callbacks, fetchSession);
  }

  /**
   * Safely unregisters either the mutation owner or a registered terminal
   * observer from the active lookup.
   */
  unsubscribe(
    callback?: RemoteAuditLookupCallback | RemoteAuditLookupTerminalObserver,
  ): void {
    if (callback && this.inFlightIntent) {
      if (isRegisteredTerminalObserver(callback)) {
        this.inFlightIntent.terminalObservers.delete(
          callback as RemoteAuditLookupTerminalObserver,
        );
      } else if (this.inFlightIntent.mutationOwner === callback) {
        this.inFlightIntent.mutationOwner = undefined;
      }
    }
  }

  abort(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    if (this.inFlightIntent) {
      this.inFlightIntent.terminalObservers.clear();
      this.inFlightIntent.mutationOwner = undefined;
      this.inFlightIntent = null;
    }
    this.generation += 1;
  }

  destroy(): void {
    this.abort();
    this.currentSessionId = null;
    this.currentTargetHopId = null;
    this.callbacks = undefined;
  }
}

export { RemoteAuditLookupCoordinator as RemoteAuditLookupManager };

export interface CreateRemoteAuditLookupCallbacksOptions {
  recordLookedUpSession: (session: FilesystemClosedSession) => void;
  setExtraAuditSessions: (updater: (prev: Map<string, FilesystemTopologySession | FilesystemClosedSession>) => Map<string, FilesystemTopologySession | FilesystemClosedSession>) => void;
  setExpiredSessionId: (sessionId: string | null) => void;
  selectSession: (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession, targetHopId?: string | null) => void;
  setSelectedSessionId?: (sessionId: string | null) => void;
  selectedSessionIdRef?: { current: string | null };
  clearSelectedSessionRef?: () => void;
}

export function createRemoteAuditLookupCallbacks(
  options: CreateRemoteAuditLookupCallbacksOptions,
): RemoteAuditLookupCallback {
  return {
    onSessionFound: (found, targetHopId) => {
      options.recordLookedUpSession(found);
      options.setExtraAuditSessions((prev) => {
        if (prev.has(found.sessionId)) return prev;
        const next = new Map(prev);
        next.set(found.sessionId, found);
        return next;
      });
      options.setExpiredSessionId(null);
      options.selectSession(found.sessionId, found, targetHopId);
    },
    onSessionNotFound: (targetId) => {
      options.setExpiredSessionId(targetId);
      if (options.clearSelectedSessionRef) {
        options.clearSelectedSessionRef();
      } else if (options.selectedSessionIdRef) {
        options.selectedSessionIdRef.current = null;
      }
      options.setSelectedSessionId?.(null);
    },
  };
}
export interface AdoptLocalSessionScopeParams {
  coordinator?: RemoteAuditLookupCoordinator | null;
  viewMode: "live" | "audit";
  sessionId: string;
  targetHopId?: string | null;
}

export function adoptLocalSessionScope(params: AdoptLocalSessionScopeParams): string | null {
  const { coordinator, viewMode, sessionId, targetHopId } = params;
  const effectiveHop = viewMode === "live" ? null : normalizeHop(targetHopId);

  if (coordinator) {
    coordinator.adoptLocalSessionScope(sessionId, effectiveHop, viewMode);
  }

  return effectiveHop;
}

export interface ProcessSnapshotSessionResolutionParams {
  snapshot: FilesystemTopologySnapshot;
  extraAuditSessions: Map<string, FilesystemTopologySession | FilesystemClosedSession>;
  requestedSessionIdRef: { current: string | null };
  selectedSessionIdRef: { current: string | null };
  requestedHopRef: { current: string | null };
  viewMode: "live" | "audit";
  lookupRemoteAuditSession: (intent: RemoteAuditLookupIntent) => Promise<void> | void;
  setExpiredSessionId: (id: string | null) => void;
  setSelectedSessionId: (id: string | null) => void;
  coordinator?: RemoteAuditLookupCoordinator | null;
}

export function processSnapshotSessionResolution(
  params: ProcessSnapshotSessionResolutionParams,
): SessionResolutionResult {
  const knownSessions = [
    ...params.snapshot.sessions,
    ...params.snapshot.recentClosedSessions,
    ...params.extraAuditSessions.values(),
  ];
  const candidateId = params.requestedSessionIdRef.current ?? params.selectedSessionIdRef.current;
  const resolution = resolveSessionSelection(
    params.requestedSessionIdRef.current,
    params.selectedSessionIdRef.current,
    knownSessions,
    params.viewMode === "audit",
  );
  params.requestedSessionIdRef.current = null;

  if (resolution.expiredSessionId) {
    if (params.viewMode === "audit" && candidateId) {
      void params.lookupRemoteAuditSession({
        sessionId: candidateId,
        targetHopId: params.requestedHopRef.current,
      });
    } else {
      params.setExpiredSessionId(resolution.expiredSessionId);
      params.selectedSessionIdRef.current = null;
      params.setSelectedSessionId(null);
    }
  } else {
    params.setExpiredSessionId(null);
    params.selectedSessionIdRef.current = resolution.sessionId;
    params.setSelectedSessionId(resolution.sessionId);
    if (resolution.sessionId) {
      const effectiveHop = adoptLocalSessionScope({
        coordinator: params.coordinator,
        viewMode: params.viewMode,
        sessionId: resolution.sessionId,
        targetHopId: params.requestedHopRef.current,
      });
      if (params.viewMode === "live") {
        params.requestedHopRef.current = null;
      } else if (effectiveHop !== null) {
        params.requestedHopRef.current = effectiveHop;
      }
    } else if (params.viewMode === "live") {
      params.requestedHopRef.current = null;
      params.coordinator?.notifyNavigationScope({
        viewMode: "live",
        sessionId: null,
        targetHopId: null,
      });
    }
  }

  return resolution;
}
