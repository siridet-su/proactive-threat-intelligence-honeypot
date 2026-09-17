import type { AuditSessionsPage, FilesystemClosedSession } from "@/lib/dashboardTypes";

export type CloseReason = "escape" | "select" | "toggle" | "outside";

export interface StandaloneSearchScope {
  openCycle: number;
  generation: number;
  query: string;
  hideHomeOnly: boolean;
  targetPathFilter: string | null;
  cursor: string | null;
}

export interface AuditSessionSearchManagerOptions {
  onSearch?: (query: string) => void;
  onClearSearch?: () => void;
  onLoadMoreSearch?: () => void;
  onLoadMoreDirectory?: () => void;
  hideHomeOnly?: boolean;
  targetPathFilter?: string | null;
  debounceMs?: number;
}

export interface AuditSessionSearchState {
  isOpen: boolean;
  openCycle: number;
  searchQuery: string;
  remoteSessions: FilesystemClosedSession[];
  remoteCursor: string | null;
  hasMoreRemote: boolean;
  isLoadingRemote: boolean;
  errorMessage: string | null;
  searchGeneration: number;
}

/**
 * Authoritative lifecycle owner for AuditSessionSelect (FA-007).
 *
 * Guarantees:
 * 1. Synchronous & idempotent close: close(reason) returns false if already closed; onClearSearch
 *    fires exactly once per logical close cycle.
 * 2. Active debounce timers are cancelled immediately on close, clear, query wipe, or unmount.
 * 3. Standalone HTTP searches use AbortController, bound to complete scope:
 *    { openCycle, generation, query, hideHomeOnly, targetPathFilter, cursor }.
 * 4. Stale responses across query changes, filter changes, re-opens, or unmounts cannot mutate UI state.
 * 5. Re-opening never exposes results from previous search query.
 * 6. Synchronized with React via useSyncExternalStore.
 */
export class AuditSessionSearchManager {
  private state: AuditSessionSearchState;
  private options: AuditSessionSearchManagerOptions;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private activeAbortController: AbortController | null = null;
  private listeners = new Set<() => void>();

  constructor(options: AuditSessionSearchManagerOptions = {}) {
    this.options = options;
    this.state = {
      isOpen: false,
      openCycle: 0,
      searchQuery: "",
      remoteSessions: [],
      remoteCursor: null,
      hasMoreRemote: false,
      isLoadingRemote: false,
      errorMessage: null,
      searchGeneration: 0,
    };
  }

  public updateOptions(options: AuditSessionSearchManagerOptions): void {
    const prevHideHome = this.options.hideHomeOnly;
    const prevTargetPath = this.options.targetPathFilter;
    this.options = options;

    // If filter scope changed while open in standalone search mode:
    if (
      this.state.isOpen &&
      !this.options.onSearch &&
      (prevHideHome !== options.hideHomeOnly || prevTargetPath !== options.targetPathFilter)
    ) {
      const trimmed = this.state.searchQuery.trim();
      this.cancelDebounce();
      this.abortInFlight();
      const currentGen = ++this.state.searchGeneration;
      this.updateState({
        remoteSessions: [],
        remoteCursor: null,
        hasMoreRemote: false,
        isLoadingRemote: false,
        errorMessage: null,
        searchGeneration: currentGen,
      });
      if (trimmed) {
        this.scheduleStandaloneSearch(trimmed, currentGen);
      }
    }
  }

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  public getSnapshot = (): AuditSessionSearchState => {
    return this.state;
  };

  private notify(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }

  private updateState(partial: Partial<AuditSessionSearchState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  public getIsOpen(): boolean {
    return this.state.isOpen;
  }

  public getSearchQuery(): string {
    return this.state.searchQuery;
  }

  public getRemoteSessions(): readonly FilesystemClosedSession[] {
    return this.state.remoteSessions;
  }

  public getRemoteCursor(): string | null {
    return this.state.remoteCursor;
  }

  public getHasMoreRemote(): boolean {
    return this.state.hasMoreRemote;
  }

  public getIsLoadingRemote(): boolean {
    return this.state.isLoadingRemote;
  }

  public getSearchGeneration(): number {
    return this.state.searchGeneration;
  }

  public getOpenCycle(): number {
    return this.state.openCycle;
  }

  public isDebouncePending(): boolean {
    return this.debounceTimer !== null;
  }

  public open(): void {
    if (this.state.isOpen) return;
    this.cancelDebounce();
    this.abortInFlight();
    this.updateState({
      isOpen: true,
      openCycle: this.state.openCycle + 1,
      searchQuery: "",
      remoteSessions: [],
      remoteCursor: null,
      hasMoreRemote: false,
      isLoadingRemote: false,
      errorMessage: null,
      searchGeneration: this.state.searchGeneration + 1,
    });
  }

  public close(reason: CloseReason = "escape"): boolean {
    void reason;
    if (!this.state.isOpen) {
      return false; // Idempotent!
    }
    this.cancelDebounce();
    this.abortInFlight();
    this.updateState({
      isOpen: false,
      openCycle: this.state.openCycle + 1,
      searchQuery: "",
      remoteSessions: [],
      remoteCursor: null,
      hasMoreRemote: false,
      isLoadingRemote: false,
      errorMessage: null,
      searchGeneration: this.state.searchGeneration + 1,
    });
    this.options.onClearSearch?.();
    return true;
  }

  public clearSearch(): void {
    this.cancelDebounce();
    this.abortInFlight();
    this.updateState({
      searchQuery: "",
      remoteSessions: [],
      remoteCursor: null,
      hasMoreRemote: false,
      isLoadingRemote: false,
      errorMessage: null,
      searchGeneration: this.state.searchGeneration + 1,
    });
    this.options.onClearSearch?.();
  }

  public setSearchQuery(value: string): void {
    this.cancelDebounce();
    this.abortInFlight();
    const trimmed = value.trim();

    if (!trimmed) {
      const nextGen = this.state.searchGeneration + 1;
      this.updateState({
        searchQuery: value,
        remoteSessions: [],
        remoteCursor: null,
        hasMoreRemote: false,
        isLoadingRemote: false,
        errorMessage: null,
        searchGeneration: nextGen,
      });
      this.options.onClearSearch?.();
      return;
    }

    const nextGen = this.state.searchGeneration + 1;
    this.updateState({
      searchQuery: value,
      isLoadingRemote: false,
      errorMessage: null,
      searchGeneration: nextGen,
    });

    const debounceMs = this.options.debounceMs ?? 250;
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      if (!this.state.isOpen || this.state.searchGeneration !== nextGen) {
        return;
      }
      if (this.options.onSearch) {
        // Parent-controlled search (FA-001 / FA-002)
        this.options.onSearch(trimmed);
      } else {
        // Standalone fallback search
        void this.executeStandaloneSearch(trimmed, nextGen, null);
      }
    }, debounceMs);
  }

  public cancelDebounce(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  public abortInFlight(): void {
    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = null;
    }
  }

  private scheduleStandaloneSearch(trimmed: string, generation: number): void {
    const debounceMs = this.options.debounceMs ?? 250;
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      if (!this.state.isOpen || this.state.searchGeneration !== generation) {
        return;
      }
      void this.executeStandaloneSearch(trimmed, generation, null);
    }, debounceMs);
  }

  public async loadMore(): Promise<void> {
    if (!this.state.isOpen || this.state.isLoadingRemote) return;

    if (this.state.searchQuery.trim()) {
      if (this.options.onLoadMoreSearch) {
        this.options.onLoadMoreSearch();
        return;
      }
      // Standalone load more
      if (!this.state.hasMoreRemote || !this.state.remoteCursor) return;
      await this.executeStandaloneSearch(
        this.state.searchQuery.trim(),
        this.state.searchGeneration,
        this.state.remoteCursor,
      );
    } else {
      if (this.options.onLoadMoreDirectory) {
        this.options.onLoadMoreDirectory();
      }
    }
  }

  public async executeStandaloneSearch(
    query: string,
    generation: number,
    cursor: string | null,
  ): Promise<void> {
    const scope: StandaloneSearchScope = {
      openCycle: this.state.openCycle,
      generation,
      query,
      hideHomeOnly: Boolean(this.options.hideHomeOnly),
      targetPathFilter: this.options.targetPathFilter ?? null,
      cursor,
    };

    this.abortInFlight();
    const controller = new AbortController();
    this.activeAbortController = controller;

    this.updateState({ isLoadingRemote: true, errorMessage: null });

    try {
      const params = new URLSearchParams();
      params.set("q", query);
      params.set("limit", "25");
      if (scope.hideHomeOnly) params.set("hideHome", "1");
      if (scope.targetPathFilter) params.set("targetPath", scope.targetPathFilter);
      if (scope.cursor) params.set("cursor", scope.cursor);

      const response = await fetch(
        `/api/filesystem-topology/audit-sessions?${params.toString()}`,
        {
          cache: "no-store",
          signal: controller.signal,
        },
      );

      // Validate scope after network fetch
      if (
        !this.state.isOpen ||
        this.state.openCycle !== scope.openCycle ||
        this.state.searchGeneration !== scope.generation
      ) {
        return;
      }

      if (!response.ok) {
        this.updateState({
          isLoadingRemote: false,
          errorMessage: `Search request failed (${response.status})`,
        });
        return;
      }

      const data: unknown = await response.json();

      // Validate scope after json parse
      if (
        !this.state.isOpen ||
        this.state.openCycle !== scope.openCycle ||
        this.state.searchGeneration !== scope.generation
      ) {
        return;
      }

      const page = data as Partial<AuditSessionsPage>;
      if (Array.isArray(page.items)) {
        if (scope.cursor) {
          // Append page 2+
          const seen = new Set(this.state.remoteSessions.map((s) => s.sessionId));
          const additions = page.items.filter((s) => !seen.has(s.sessionId));
          this.updateState({
            remoteSessions: [...this.state.remoteSessions, ...additions],
            remoteCursor: page.nextCursor ?? null,
            hasMoreRemote: Boolean(page.nextCursor),
            isLoadingRemote: false,
          });
        } else {
          // Page 1 replace
          this.updateState({
            remoteSessions: page.items,
            remoteCursor: page.nextCursor ?? null,
            hasMoreRemote: Boolean(page.nextCursor),
            isLoadingRemote: false,
          });
        }
      } else {
        this.updateState({ isLoadingRemote: false });
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) {
        return; // Normal cancellation
      }
      if (
        this.state.isOpen &&
        this.state.openCycle === scope.openCycle &&
        this.state.searchGeneration === scope.generation
      ) {
        this.updateState({
          isLoadingRemote: false,
          errorMessage: err instanceof Error ? err.message : "Search failed",
        });
      }
    } finally {
      if (this.activeAbortController === controller) {
        this.activeAbortController = null;
      }
    }
  }

  // Testing & manual injection hooks
  public setRemoteResults(
    page: { items?: FilesystemClosedSession[]; nextCursor?: string | null },
    generation: number,
  ): boolean {
    if (!this.state.isOpen || this.state.searchGeneration !== generation) {
      return false;
    }
    if (Array.isArray(page.items)) {
      this.updateState({
        remoteSessions: page.items,
        remoteCursor: page.nextCursor ?? null,
        hasMoreRemote: Boolean(page.nextCursor),
        isLoadingRemote: false,
      });
    } else {
      this.updateState({ isLoadingRemote: false });
    }
    return true;
  }

  public appendRemoteResults(
    page: { items?: FilesystemClosedSession[]; nextCursor?: string | null },
    generation: number,
  ): boolean {
    if (!this.state.isOpen || this.state.searchGeneration !== generation) {
      return false;
    }
    if (Array.isArray(page.items)) {
      const seen = new Set(this.state.remoteSessions.map((s) => s.sessionId));
      const additions = page.items.filter((s) => !seen.has(s.sessionId));
      this.updateState({
        remoteSessions: [...this.state.remoteSessions, ...additions],
        remoteCursor: page.nextCursor ?? null,
        hasMoreRemote: Boolean(page.nextCursor),
        isLoadingRemote: false,
      });
    } else {
      this.updateState({ isLoadingRemote: false });
    }
    return true;
  }

  public dispose(): void {
    this.cancelDebounce();
    this.abortInFlight();
    this.state.isOpen = false;
    this.listeners.clear();
  }
}
