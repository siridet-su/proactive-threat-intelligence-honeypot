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
import { createRemoteAuditLookupTerminalObserver } from "./sessionHopResolver";

export interface NavigationStateCommitOptions {
  view?: "live" | "audit";
  sessionId?: string | null;
  hideHome?: boolean;
  targetPath?: string | null;
  hop?: string | null;
}

export interface PopStateTransaction {
  id: number;
  target: AuditUrlParams;
  status: "pending" | "terminal";
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

  private markTransactionTerminal(txId: number): void {
    if (this.activeTransaction?.id === txId) {
      this.activeTransaction.status = "terminal";
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
      window.history.pushState(null, "", targetUrl);
      // Explicit user navigation invalidates any pending popstate transaction
      this.activeTransaction = null;
    } else {
      window.history.replaceState(null, "", targetUrl);
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
    const effectiveHop = nextView === "live" ? null : (parsed.hop ?? null);

    // Deduplicate if an active popstate transaction is already pending for this identical canonical target
    if (
      this.activeTransaction &&
      this.activeTransaction.status === "pending" &&
      areAuditUrlParamsEqual(this.activeTransaction.target, parsed)
    ) {
      return;
    }

    const txId = ++this.transactionCounter;
    this.activeTransaction = {
      id: txId,
      target: parsed,
      status: "pending",
    };

    // Notify lookup coordinator of authoritative scope change
    this.options.coordinator?.notifyNavigationScope({
      viewMode: nextView,
      sessionId: parsed.sessionId ?? null,
      targetHopId: effectiveHop,
    });

    // Synchronously update view & filter state
    this.options.setViewMode(nextView);
    this.options.setHideHomeOnly(Boolean(parsed.hideHome));
    this.options.setTargetPathFilter(parsed.targetPath ?? null);
    this.options.setRequestedHop(effectiveHop);
    this.options.setSelectedHistoryEventId(effectiveHop);

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
      this.options.setRequestedSessionId(null);
      this.options.setExpiredSessionId(null);
      if (nextView === "audit") {
        this.options.setSelectedSessionId(null);
      }
      this.markTransactionTerminal(txId);
    }
  }

  /**
   * Executes remote lookup for popstate with transaction generation tracking.
   *
   * Ownership model:
   * - If no lookup is in flight for this intent, this transaction becomes the
   *   authoritative "mutation owner": on success it applies domain mutations
   *   (setExtraAuditSessions, selectSession) and marks itself terminal.
   * - If a lookup is already in flight for the same intent (e.g. initiated by a
   *   snapshot update), this transaction registers only a lightweight terminal-marker
   *   as a join observer. The marker calls markTransactionTerminal and nothing else,
   *   preventing duplicate domain-state application while still ensuring the
   *   transaction completes.
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

    // Determine whether a lookup is already in flight for this exact intent.
    // A same-intent join is registered through the coordinator's terminal-only
    // observer API; a different intent must become the new mutation owner.
    const inFlightIntent = this.options.coordinator.getInFlightIntent();
    const alreadyInFlight = Boolean(
      inFlightIntent &&
        inFlightIntent.sessionId === sessionId &&
        (inFlightIntent.targetHopId ?? null) === (targetHopId ?? null),
    );

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
    const terminalObserver = alreadyInFlight
      ? createRemoteAuditLookupTerminalObserver(() => {
          if (this.activeTransaction?.id !== txId) return;
          this.markTransactionTerminal(txId);
        })
      : undefined;

    try {
      if (terminalObserver) {
        await this.options.coordinator.joinLookup(
          { sessionId, targetHopId },
          terminalObserver,
        );
      } else {
        await this.options.coordinator.lookup(
          { sessionId, targetHopId },
          mutatingCallbacks,
        );
      }
    } catch {
      // A failed authoritative application intentionally leaves the transaction
      // pending. This keeps passive URL synchronization suppressed rather than
      // claiming terminal state after partially applied domain state.
    } finally {
      if (terminalObserver) {
        this.options.coordinator.unsubscribe(terminalObserver);
      } else {
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
    if (this.isPopStatePending()) return;

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
    };

    const currentSearch = window.location.search;
    const targetSearch = buildAuditUrlSearch(targetParams);

    if (currentSearch !== targetSearch || !areAuditUrlParamsEqual(currentParams, targetParams)) {
      const targetUrl = buildAuditTargetUrl(targetParams);
      window.history.replaceState(null, "", targetUrl);
    }
  }
}
