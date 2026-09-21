import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import {
  type AuditUrlParams,
  areAuditUrlParamsEqual,
  buildAuditTargetUrl,
  buildAuditUrlSearch,
  parseAuditUrlParams,
  resolveFilterChangeWithFallback,
  resolveSessionSelection,
} from "./filesystemUtils";
import type {
  RemoteAuditLookupCoordinator,
  RemoteAuditLookupIntent,
} from "./sessionHopResolver";
import {
  createRemoteAuditLookupTerminalObserver,
  normalizeHop,
  type RemoteAuditLookupTerminalObserver,
} from "./sessionHopResolver";

export interface NavigationStateCommitOptions {
  view?: "live" | "audit";
  sessionId?: string | null;
  hideHome?: boolean;
  targetPath?: string | null;
  hop?: string | null;
  timeRange?: string | null;
  timeFrom?: number | null;
  timeTo?: number | null;
}

export interface PopStateTransaction {
  id: number;
  target: AuditUrlParams;
  status: "pending" | "terminal" | "failed";
  error?: unknown;
}

/**
 * URL and React state bindings owned by useFilesystemUrlState.
 */
export interface NavigationUrlStateBindings {
  getViewMode: () => "live" | "audit";
  setViewMode: (mode: "live" | "audit") => void;
  getSelectedSessionId: () => string | null;
  setSelectedSessionId: (id: string | null) => void;
  getHideHomeOnly: () => boolean;
  setHideHomeOnly: (hide: boolean) => void;
  getTargetPathFilter: () => string | null;
  setTargetPathFilter: (path: string | null) => void;
  getTimeRange: () => string;
  setTimeRange: (range: any) => void;
  getCustomDateRange: () => any;
  setCustomDateRange: (range: any) => void;
  getSelectedHistoryEventId: () => string | null;
  setSelectedHistoryEventId: (eventId: string | null) => void;
  getExpiredSessionId: () => string | null;
  setExpiredSessionId: (id: string | null) => void;
  getRequestedHop: () => string | null;
  setRequestedHop: (hop: string | null) => void;
  setRequestedSessionId: (sessionId: string | null) => void;
  getSnapshot: () => FilesystemTopologySnapshot | null;
  getExtraAuditSessions: () => Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  setExtraAuditSessions?: (
    updater: (
      prev: Map<string, FilesystemClosedSession | FilesystemTopologySession>,
    ) => Map<string, FilesystemClosedSession | FilesystemTopologySession>,
  ) => void;
}

/**
 * Domain adapter callbacks and data owned exclusively by FilesystemActivity.
 */
export interface NavigationDomainAdapter {
  getAllSessions: () => (FilesystemTopologySession | FilesystemClosedSession)[];
  getSessionById: () => Map<string, FilesystemTopologySession | FilesystemClosedSession>;
  selectSession: (
    sessionId: string,
    sessionObj?: FilesystemTopologySession | FilesystemClosedSession,
    targetHopId?: string | null,
  ) => void;
  recordLookedUpSession?: (session: FilesystemClosedSession) => void;
  onNavigationApplicationError?: (error: unknown, transaction: PopStateTransaction) => void;
  onNavigationTransactionStarted?: (target: AuditUrlParams) => void;
  resetHistory: () => void;
  resetRequestedHopState: () => void;
  onExitFullscreenAndPlaying?: () => void;
  coordinator?: RemoteAuditLookupCoordinator | null;
  lookupRemoteAuditSession?: (intent: RemoteAuditLookupIntent) => Promise<void> | void;
}

export type FilesystemNavigationCoordinatorOptions = NavigationUrlStateBindings & NavigationDomainAdapter;

/**
 * FilesystemNavigationCoordinator
 *
 * Centralizes all user-driven navigation, browser Back/Forward (popstate) transactions,
 * and background URL synchronization for Filesystem Activity.
 *
 * Guarantees:
 * 1. Intentional user actions push exactly once and deduplicate identical state.
 * 2. Automated background sync and playback tick use replaceState without flooding history.
 * 3. Popstate transactions protect the popped URL from being overwritten by stale React state
 *    until the navigation reaches a terminal state (session adopted, expired, or superseded).
 * 4. Rapid Back/Forward invalidates superseded transactions and discards stale in-flight results.
 * 5. Internal hop cleanups never create intermediate history writes.
 */
export const DEFAULT_COORDINATOR_OPTIONS: FilesystemNavigationCoordinatorOptions = {
  getViewMode: () => "live",
  getSelectedSessionId: () => null,
  getHideHomeOnly: () => false,
  getTargetPathFilter: () => null,
  getSelectedHistoryEventId: () => null,
  getRequestedHop: () => null,
  getExpiredSessionId: () => null,
  getSnapshot: () => null,
  getExtraAuditSessions: () => new Map(),
  getAllSessions: () => [],
  getSessionById: () => new Map(),

  setViewMode: () => {},
  setHideHomeOnly: () => {},
  setTargetPathFilter: () => {},
  getTimeRange: () => "all",
  setTimeRange: () => {},
  getCustomDateRange: () => undefined,
  setCustomDateRange: () => {},
  setSelectedHistoryEventId: () => {},
  setExpiredSessionId: () => {},
  setSelectedSessionId: () => {},
  setRequestedHop: () => {},
  setRequestedSessionId: () => {},

  selectSession: () => {},
  resetHistory: () => {},
  resetRequestedHopState: () => {},
};

export class FilesystemNavigationCoordinator {
  private options: FilesystemNavigationCoordinatorOptions;
  private transactionCounter = 0;
  private activeTransaction: PopStateTransaction | null = null;
  /** Keeps the failed URL authoritative after explicit recovery releases tx state. */
  private recoveredTransactionTarget: AuditUrlParams | null = null;

  constructor(options: FilesystemNavigationCoordinatorOptions = DEFAULT_COORDINATOR_OPTIONS) {
    this.options = options;
  }

  /**
   * Binds URL state getters and setters owned exclusively by useFilesystemUrlState.
   * Does not touch or overwrite domain adapter callbacks.
   */
  bindUrlState(bindings: NavigationUrlStateBindings): void {
    this.options = { ...this.options, ...bindings };
  }

  /**
   * Binds domain callbacks and session accessors owned exclusively by FilesystemActivity.
   * Does not touch or overwrite URL state bindings.
   */
  bindDomainAdapter(adapter: NavigationDomainAdapter): void {
    this.options = { ...this.options, ...adapter };
  }

  /**
   * Updates coordinator options without overwriting existing production callbacks with undefined.
   */
  updateOptions(options: Partial<FilesystemNavigationCoordinatorOptions>): void {
    const next = { ...this.options };
    for (const key of Object.keys(options) as (keyof FilesystemNavigationCoordinatorOptions)[]) {
      const val = options[key];
      if (val !== undefined) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (next as any)[key] = val;
      }
    }
    this.options = next;
  }

  getActiveTransaction(): PopStateTransaction | null {
    return this.activeTransaction ? { ...this.activeTransaction } : null;
  }

  isPopStatePending(): boolean {
    return this.activeTransaction !== null && this.activeTransaction.status === "pending";
  }

  /**
   * Explicitly releases a recoverably failed transaction. This does not write
   * history or derive a replacement URL from potentially stale React state.
   * A short-lived URL guard keeps passive synchronization from immediately
   * replacing the failed target with stale state; a new popstate or explicit
   * user push clears the guard.
   */
  recoverFailedTransaction(): boolean {
    if (!this.activeTransaction || this.activeTransaction.status !== "failed") {
      return false;
    }
    this.recoveredTransactionTarget = { ...this.activeTransaction.target };
    this.activeTransaction = null;
    return true;
  }

  private markTransactionTerminal(txId: number): void {
    if (this.activeTransaction?.id === txId) {
      this.activeTransaction.status = "terminal";
      this.activeTransaction.error = undefined;
    }
  }

  private markTransactionFailed(txId: number, error: unknown): void {
    if (this.activeTransaction?.id !== txId) return;
    this.activeTransaction.status = "failed";
    this.activeTransaction.error = error;
    try {
      this.options.onNavigationApplicationError?.(error, { ...this.activeTransaction });
    } catch {
      // Error reporting must not replace the original recoverable transaction
      // state or make a failed navigation appear successfully adopted.
    }
  }

  /**
   * Centralized URL commitment logic.
   * Compares proposed target params with current location.search.
   * If identical, returns false (deduplicated).
   * Otherwise applies pushState or replaceState and returns true.
   */
  commit(updates: NavigationStateCommitOptions, mode: "push" | "replace"): boolean {
    if (typeof window === "undefined") return false;

    const currentParams = parseAuditUrlParams(window.location.search);
    const targetView = updates.view ?? this.options.getViewMode();
    const targetHop =
      targetView === "live"
        ? null
        : updates.hop !== undefined
          ? updates.hop
          : (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop());

    const targetParams: AuditUrlParams = {
      view: targetView,
      sessionId:
        updates.sessionId !== undefined
          ? updates.sessionId
          : (this.options.getSelectedSessionId() ?? this.options.getExpiredSessionId()),
      hideHome: updates.hideHome !== undefined ? updates.hideHome : this.options.getHideHomeOnly(),
      targetPath:
        updates.targetPath !== undefined
          ? updates.targetPath
          : this.options.getTargetPathFilter(),
      hop: targetHop,
    };

    const currentSearch = window.location.search;
    const targetSearch = buildAuditUrlSearch(targetParams);

    if (currentSearch === targetSearch && areAuditUrlParamsEqual(currentParams, targetParams)) {
      return false;
    }

    const targetUrl = buildAuditTargetUrl(targetParams);
    if (mode === "push") {
      this.recoveredTransactionTarget = null;
      window.history.pushState(null, "", targetUrl);
      // Explicit user navigation invalidates any pending popstate transaction
      this.activeTransaction = null;
    } else {
      // Passive reconciliation must preserve Next.js' current app-router
      // state. Passing null makes Next treat the replacement as an external
      // history mutation while a same-document traversal may be in flight.
      window.history.replaceState(window.history.state, "", targetUrl);
    }
    return true;
  }

  /**
   * User action: select another session.
   * Clears hop and creates exactly 1 pushState entry.
   * Internal state cleanup performs no additional history writes.
   */
  userSelectSession(
    sessionId: string,
    sessionObj?: FilesystemTopologySession | FilesystemClosedSession,
  ): void {
    const currentMode = this.options.getViewMode();
    // 1. Commit canonical destination first
    this.commit(
      {
        view: currentMode,
        sessionId,
        hop: null,
      },
      "push",
    );

    // 2. Apply internal coordinator & React state without further history writes
    this.options.coordinator?.notifyNavigationScope({
      viewMode: currentMode,
      sessionId,
      targetHopId: null,
    });
    this.options.resetRequestedHopState();
    this.options.setSelectedHistoryEventId(null);
    this.options.selectSession(sessionId, sessionObj, null);
  }

  /**
   * User action: toggle hideHome filter.
   * Calculates fallback session atomically, pushing exactly 1 history entry.
   */
  userToggleHideHome(): void {
    const result = resolveFilterChangeWithFallback({
      filterType: "hideHome",
      hideHomeOnly: this.options.getHideHomeOnly(),
      targetPathFilter: this.options.getTargetPathFilter(),
      selectedSessionId: this.options.getSelectedSessionId(),
      allSessions: this.options.getAllSessions(),
      sessionById: this.options.getSessionById(),
    });

    const targetHop = result.sessionChanged
      ? null
      : (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop());

    // 1. Commit complete destination first
    this.commit(
      {
        view: "audit",
        sessionId: result.nextSessionId,
        hideHome: result.nextHideHome,
        targetPath: this.options.getTargetPathFilter(),
        hop: targetHop,
      },
      "push",
    );

    // 2. Apply internal state
    this.options.setHideHomeOnly(result.nextHideHome);
    if (result.sessionChanged && result.nextSessionId) {
      this.options.resetRequestedHopState();
      this.options.setSelectedHistoryEventId(null);
      this.options.selectSession(result.nextSessionId);
    }
  }

  /**
   * User action: select target path filter.
   * Calculates fallback session atomically, pushing exactly 1 history entry.
   */
  userSelectTargetPath(path: string | null): void {
    const result = resolveFilterChangeWithFallback({
      filterType: "targetPath",
      proposedTargetPath: path,
      hideHomeOnly: this.options.getHideHomeOnly(),
      targetPathFilter: this.options.getTargetPathFilter(),
      selectedSessionId: this.options.getSelectedSessionId(),
      allSessions: this.options.getAllSessions(),
      sessionById: this.options.getSessionById(),
    });

    const targetHop = result.sessionChanged
      ? null
      : (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop());

    // 1. Commit complete destination first
    this.commit(
      {
        view: "audit",
        sessionId: result.nextSessionId,
        hideHome: this.options.getHideHomeOnly(),
        targetPath: result.nextTargetPath,
        hop: targetHop,
      },
      "push",
    );

    // 2. Apply internal state
    this.options.setTargetPathFilter(result.nextTargetPath);
    if (result.sessionChanged && result.nextSessionId) {
      this.options.resetRequestedHopState();
      this.options.setSelectedHistoryEventId(null);
      this.options.selectSession(result.nextSessionId);
    }
  }

  /**
   * User action: reset audit filters.
   * Resets hideHome to false and targetPath to null while preserving active session & hop.
   * Pushes exactly 1 entry. Deduplicated if filters are already default.
   */
  userResetFilters(): void {
    if (!this.options.getHideHomeOnly() && this.options.getTargetPathFilter() === null) {
      return;
    }

    const currentSession = this.options.getSelectedSessionId();
    const currentHop = this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop();

    this.commit(
      {
        view: this.options.getViewMode(),
        sessionId: currentSession,
        hideHome: false,
        targetPath: null,
        hop: currentHop,
      },
      "push",
    );

    this.options.setHideHomeOnly(false);
    this.options.setTargetPathFilter(null);
    this.options.setTimeRange("all");
    this.options.setCustomDateRange(undefined);
  }

  /**
   * User action: clear selected session.
   * Pushes exactly 1 entry with sessionId=null and hop=null, preserving active filters.
   * Cancels in-flight lookup and hop work. Deduplicated if already null.
   */
  userClearSelection(): void {
    if (
      this.options.getSelectedSessionId() === null &&
      (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop()) === null
    ) {
      return;
    }

    const currentMode = this.options.getViewMode();
    this.commit(
      {
        view: currentMode,
        sessionId: null,
        hideHome: this.options.getHideHomeOnly(),
        targetPath: this.options.getTargetPathFilter(),
        hop: null,
      },
      "push",
    );

    this.options.coordinator?.notifyNavigationScope({
      viewMode: currentMode,
      sessionId: null,
      targetHopId: null,
    });
    this.options.coordinator?.abort();
    this.options.resetRequestedHopState();
    this.options.setSelectedHistoryEventId(null);
    this.options.setSelectedSessionId(null);
    this.options.resetHistory();
  }

  /**
   * User action: select hop (manual route click, prev, next).
   * Pushes exactly 1 entry.
   */
  userSelectHop(hopId: string | null): void {
    if (this.options.getViewMode() !== "audit") return;

    this.commit(
      {
        view: "audit",
        sessionId: this.options.getSelectedSessionId(),
        hop: hopId,
      },
      "push",
    );

    this.options.setRequestedHop(hopId);
    this.options.setSelectedHistoryEventId(hopId);
  }

  /**
   * User action: explicit Clear hop button click.
   * Pushes exactly 1 entry with hop=null.
   */
  userClearHop(): void {
    this.userSelectHop(null);
  }

  /**
   * Automated action: replay playback tick.
   * Uses replaceState without increasing history length.
   */
  playbackSelectHop(hopId: string | null): void {
    if (this.options.getViewMode() !== "audit") return;

    this.commit(
      {
        view: "audit",
        sessionId: this.options.getSelectedSessionId(),
        hop: hopId,
      },
      "replace",
    );

    this.options.setRequestedHop(hopId);
    this.options.setSelectedHistoryEventId(hopId);
  }

  /**
   * User action: switch view mode between live and audit.
   * Normalizes live mode to force hop=null without intermediate entries.
   */
  userSelectViewMode(mode: "live" | "audit", targetSessionId?: string): void {
    if (mode === "live") {
      this.options.onExitFullscreenAndPlaying?.();
    }

    const snapshot = this.options.getSnapshot();
    const sid =
      targetSessionId ??
      this.options.getSelectedSessionId() ??
      snapshot?.sessions[0]?.sessionId ??
      snapshot?.recentClosedSessions[0]?.sessionId ??
      null;

    const targetHop =
      mode === "live"
        ? null
        : (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop());

    this.commit(
      {
        view: mode,
        sessionId: sid,
        hop: targetHop,
      },
      "push",
    );

    this.options.coordinator?.notifyNavigationScope({
      viewMode: mode,
      sessionId: sid,
      targetHopId: targetHop,
    });

    if (mode === "live") {
      this.options.resetRequestedHopState();
      this.options.setSelectedHistoryEventId(null);
    }
    this.options.setViewMode(mode);
    this.options.setExpiredSessionId(null);
    if (mode === "audit" && sid) {
      this.options.selectSession(sid);
    }
  }

  /**
   * Popstate event handler.
   * Creates a durable pending transaction, updates synchronous UI filters,
   * coordinates remote lookups, and guards against stale URL overwrite loops.
   */
  handlePopState(searchString: string): void {
    const parsed = parseAuditUrlParams(searchString);
    const nextView = parsed.view ?? "live";
    const effectiveHop = nextView === "live" ? null : normalizeHop(parsed.hop);
    const canonicalTarget: AuditUrlParams = {
      ...parsed,
      view: nextView,
      hop: effectiveHop,
    };

    // Deduplicate if an active popstate transaction is already pending for this identical canonical target
    if (
      this.activeTransaction &&
      this.activeTransaction.status === "pending" &&
      areAuditUrlParamsEqual(this.activeTransaction.target, canonicalTarget)
    ) {
      return;
    }

    // A new canonical target supersedes any previously failed transaction.
    // The callback is deliberately outside the lookup lifecycle and cannot
    // make a failed URL appear successfully adopted.
    try {
      this.options.onNavigationTransactionStarted?.(canonicalTarget);
    } catch {
      // Error-state cleanup must never prevent the new transaction from being
      // registered or the popped URL from remaining authoritative.
    }

    const txId = ++this.transactionCounter;
    this.recoveredTransactionTarget = null;
    this.activeTransaction = {
      id: txId,
      target: canonicalTarget,
      status: "pending",
    };

    // Notify lookup coordinator of authoritative scope change
    this.options.coordinator?.notifyNavigationScope({
      viewMode: nextView,
      sessionId: parsed.sessionId ?? null,
      targetHopId: effectiveHop,
    });

    const deferLiveRestoration = nextView === "live" && !parsed.sessionId;
    if (!deferLiveRestoration) {
      // Synchronously update view & filter state for audit restoration and
      // retain the existing pending-lookup semantics.
      this.options.setViewMode(nextView);
      this.options.setHideHomeOnly(Boolean(parsed.hideHome));
      this.options.setTargetPathFilter(parsed.targetPath ?? null);
      if (parsed.timeRange) {
        this.options.setTimeRange(parsed.timeRange);
      } else {
        this.options.setTimeRange("all");
      }
      if (parsed.timeFrom || parsed.timeTo) {
        this.options.setCustomDateRange({
          from: parsed.timeFrom ? new Date(parsed.timeFrom) : undefined,
          to: parsed.timeTo ? new Date(parsed.timeTo) : undefined,
        });
      } else {
        this.options.setCustomDateRange(undefined);
      }
      this.options.setRequestedHop(effectiveHop);
      this.options.setSelectedHistoryEventId(effectiveHop);
    }

    if (parsed.sessionId) {
      this.options.setRequestedSessionId(parsed.sessionId);
      const snapshot = this.options.getSnapshot();
      if (snapshot) {
        const known = [
          ...snapshot.sessions,
          ...snapshot.recentClosedSessions,
          ...this.options.getExtraAuditSessions().values(),
        ];
        const resolution = resolveSessionSelection(
          parsed.sessionId,
          null,
          known,
          nextView === "audit",
        );

        if (resolution.expiredSessionId) {
          if (nextView === "audit") {
            // Asynchronous lookup needed. Keep transaction pending!
            void this.executeRemoteLookupForPopState(
              txId,
              resolution.expiredSessionId,
              effectiveHop,
            );
          } else {
            this.options.setExpiredSessionId(resolution.expiredSessionId);
            this.options.setSelectedSessionId(null);
            this.markTransactionTerminal(txId);
          }
        } else {
          this.options.setExpiredSessionId(null);
          if (resolution.sessionId) {
            this.options.selectSession(resolution.sessionId, undefined, effectiveHop);
          }
          this.markTransactionTerminal(txId);
        }
      } else {
        this.options.setSelectedSessionId(parsed.sessionId);
        this.markTransactionTerminal(txId);
      }
    } else {
      queueMicrotask(() => {
        if (this.activeTransaction?.id !== txId) return;
        this.options.setViewMode(nextView);
        this.options.setHideHomeOnly(Boolean(parsed.hideHome));
        this.options.setTargetPathFilter(parsed.targetPath ?? null);
        if (parsed.timeRange) {
          this.options.setTimeRange(parsed.timeRange);
        } else {
          this.options.setTimeRange("all");
        }
        if (parsed.timeFrom || parsed.timeTo) {
          this.options.setCustomDateRange({
            from: parsed.timeFrom ? new Date(parsed.timeFrom) : undefined,
            to: parsed.timeTo ? new Date(parsed.timeTo) : undefined,
          });
        } else {
          this.options.setCustomDateRange(undefined);
        }
        this.options.setRequestedHop(effectiveHop);
        this.options.setSelectedHistoryEventId(effectiveHop);
        this.options.setRequestedSessionId(null);
        this.options.setExpiredSessionId(null);
        if (nextView === "audit") {
          this.options.setSelectedSessionId(null);
        } else {
          // Live is a session-free scope. Clear the domain selection and its
          // retained route before completing the restoration so a stale audit
          // session cannot participate in the next render or URL sync pass.
          this.options.setSelectedSessionId(null);
          this.options.resetRequestedHopState();
          this.options.resetHistory();
        }
        this.markTransactionTerminal(txId);
      });
      return;
    }
  }

  /**
   * Executes remote lookup for popstate with transaction generation tracking.
   *
   * Ownership model:
   * - If no lookup is in flight for this intent, this transaction becomes the
   *   authoritative "mutation owner": on success it applies domain mutations
   *   (setExtraAuditSessions, selectSession) and marks itself terminal.
   * - If a lookup is already in flight for the same normalized intent (e.g.
   *   initiated by a snapshot update), this transaction either claims an
   *   ownerless lookup or registers only a lightweight terminal marker. The
   *   marker performs no domain application.
   *
   * If a newer popstate or user navigation supersedes txId, callbacks are discarded.
   */
  private async executeRemoteLookupForPopState(
    txId: number,
    sessionId: string,
    targetHopId: string | null,
  ): Promise<void> {
    if (!this.options.coordinator) {
      this.markTransactionTerminal(txId);
      return;
    }

    // Determine whether a lookup is already in flight for this exact normalized
    // intent. The coordinator owns normalization and equality; this layer does
    // not reproduce that comparison.
    const alreadyInFlight = this.options.coordinator.isIntentInFlight({
      sessionId,
      targetHopId,
    });

    // Full mutation callbacks used when THIS transaction starts the lookup
    const mutatingCallbacks = {
      onSessionFound: (session: FilesystemClosedSession, resolvedHopId?: string | null) => {
        if (this.activeTransaction?.id !== txId) return; // Superseded! Discard!
        this.options.recordLookedUpSession?.(session);
        if (this.activeTransaction?.id !== txId) return;
        this.options.setExtraAuditSessions?.((prev) => {
          if (prev.has(session.sessionId)) return prev;
          const next = new Map(prev);
          next.set(session.sessionId, session);
          return next;
        });
        if (this.activeTransaction?.id !== txId) return;
        this.options.setExpiredSessionId(null);
        if (this.activeTransaction?.id !== txId) return;
        this.options.selectSession(session.sessionId, session, resolvedHopId ?? null);
        // The transaction is terminal only after every authoritative state
        // application above completed successfully.
        this.markTransactionTerminal(txId);
      },
      onSessionNotFound: (targetId: string) => {
        if (this.activeTransaction?.id !== txId) return; // Superseded! Discard!
        this.options.setExpiredSessionId(targetId);
        if (this.activeTransaction?.id !== txId) return;
        this.options.setSelectedSessionId(null);
        this.markTransactionTerminal(txId);
      },
    };

    // Lightweight terminal-only observer used when joining an existing lookup.
    // It has no RemoteAuditLookupCallback shape and therefore cannot become an
    // authoritative domain mutation owner.
    let terminalObserver: RemoteAuditLookupTerminalObserver | undefined;
    let registeredMutationOwner = false;

    try {
      if (alreadyInFlight) {
        const ownerClaim = this.options.coordinator.claimMutationOwner(
          { sessionId, targetHopId },
          mutatingCallbacks,
        );
        if (ownerClaim.claimed) {
          registeredMutationOwner = true;
          await ownerClaim.promise;
        } else {
          terminalObserver = createRemoteAuditLookupTerminalObserver(() => {
            if (this.activeTransaction?.id !== txId) return;
            this.markTransactionTerminal(txId);
          });
          await this.options.coordinator.joinLookup(
            { sessionId, targetHopId },
            terminalObserver,
          );
        }
      } else {
        registeredMutationOwner = true;
        await this.options.coordinator.lookup(
          { sessionId, targetHopId },
          mutatingCallbacks,
        );
      }
    } catch (error) {
      // A failed authoritative application becomes explicitly recoverable:
      // it is not terminal-success, but it also cannot suppress URL sync
      // forever or deduplicate a retry of the same target.
      this.markTransactionFailed(txId, error);
    } finally {
      if (terminalObserver) {
        this.options.coordinator.unsubscribe(terminalObserver);
      } else if (registeredMutationOwner) {
        this.options.coordinator.unsubscribe(mutatingCallbacks);
      }
    }
  }

  /**
   * Passive URL synchronization.
   * Guaranteed not to overwrite pending popstate targets with stale React state.
   * Uses replaceState only.
   */
  synchronizeUrlState(): void {
    if (typeof window === "undefined") return;
    if (this.activeTransaction && this.activeTransaction.status !== "terminal") return;

    const currentParams = parseAuditUrlParams(window.location.search);
    const currentSession =
      this.options.getSelectedSessionId() ?? this.options.getExpiredSessionId();
    const targetParams: AuditUrlParams = {
      view: this.options.getViewMode(),
      sessionId: currentSession,
      hideHome: this.options.getHideHomeOnly(),
      targetPath: this.options.getTargetPathFilter(),
      hop:
        this.options.getViewMode() === "live"
          ? null
        : (this.options.getSelectedHistoryEventId() ?? this.options.getRequestedHop()),
      timeRange: this.options.getTimeRange(),
      timeFrom: this.options.getCustomDateRange()?.from?.getTime() ?? null,
      timeTo: this.options.getCustomDateRange()?.to?.getTime() ?? null,
    };

    if (this.recoveredTransactionTarget) {
      const stateMatchesRecoveredTarget = areAuditUrlParamsEqual(
        targetParams,
        this.recoveredTransactionTarget,
      );
      if (stateMatchesRecoveredTarget) {
        this.recoveredTransactionTarget = null;
      } else if (areAuditUrlParamsEqual(currentParams, this.recoveredTransactionTarget)) {
        // Explicit recovery released the transaction but did not authorize
        // stale state to rewrite the still-popped URL.
        return;
      } else {
        this.recoveredTransactionTarget = null;
      }
    }

    const currentSearch = window.location.search;
    const targetSearch = buildAuditUrlSearch(targetParams);

    // A completed browser restoration owns its popped canonical URL. When the
    // reconciled state already matches that target, passive effects must not
    // feed the same URL back through the history API while Next is completing
    // its same-document traversal.
    if (
      this.activeTransaction?.status === "terminal" &&
      areAuditUrlParamsEqual(currentParams, this.activeTransaction.target) &&
      areAuditUrlParamsEqual(targetParams, this.activeTransaction.target) &&
      currentSearch === targetSearch
    ) {
      return;
    }

    if (currentSearch !== targetSearch || !areAuditUrlParamsEqual(currentParams, targetParams)) {
      const targetUrl = buildAuditTargetUrl(targetParams);
      window.history.replaceState(window.history.state, "", targetUrl);
    }
  }
}
