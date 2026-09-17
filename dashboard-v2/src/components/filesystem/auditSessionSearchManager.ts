import type { FilesystemClosedSession } from "@/lib/dashboardTypes";

export interface AuditSessionSearchManagerOptions {
  onSearch?: (query: string) => void;
  onClearSearch?: () => void;
  debounceMs?: number;
}

export type CloseReason = "escape" | "select" | "toggle" | "outside";

/**
 * Manages the search and close/reset lifecycle for AuditSessionSelect (FA-007).
 *
 * Guarantees:
 * 1. Single authoritative close/reset lifecycle: onClearSearch fires exactly once per logical close/clear.
 * 2. Active debounce timers are cancelled immediately on close, clear, query wipe, or unmount.
 * 3. Generation scoping prevents late debounced search callbacks or late remote responses from
 *    mutating state after close or clear.
 * 4. State is consistently reset across all close reasons (Escape, selection, toggle, outside click).
 */
export class AuditSessionSearchManager {
  private searchQuery = "";
  private remoteSessions: FilesystemClosedSession[] = [];
  private remoteCursor: string | null = null;
  private hasMoreRemote = false;
  private isLoadingRemote = false;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private searchGeneration = 0;
  private isOpen = false;

  constructor(private options: AuditSessionSearchManagerOptions = {}) {}

  public getIsOpen(): boolean {
    return this.isOpen;
  }

  public getSearchQuery(): string {
    return this.searchQuery;
  }

  public getRemoteSessions(): readonly FilesystemClosedSession[] {
    return this.remoteSessions;
  }

  public getRemoteCursor(): string | null {
    return this.remoteCursor;
  }

  public getHasMoreRemote(): boolean {
    return this.hasMoreRemote;
  }

  public getIsLoadingRemote(): boolean {
    return this.isLoadingRemote;
  }

  public getSearchGeneration(): number {
    return this.searchGeneration;
  }

  public isDebouncePending(): boolean {
    return this.debounceTimer !== null;
  }

  public open(): void {
    this.isOpen = true;
  }

  public close(_reason?: CloseReason): void {
    void _reason;
    if (!this.isOpen && this.searchQuery === "" && this.remoteSessions.length === 0) {

      return;
    }
    this.isOpen = false;
    this.cancelDebounce();
    this.searchGeneration++;
    this.searchQuery = "";
    this.remoteSessions = [];
    this.remoteCursor = null;
    this.hasMoreRemote = false;
    this.isLoadingRemote = false;
    this.options.onClearSearch?.();
  }

  public clearSearch(): void {
    this.cancelDebounce();
    this.searchGeneration++;
    this.searchQuery = "";
    this.remoteSessions = [];
    this.remoteCursor = null;
    this.hasMoreRemote = false;
    this.isLoadingRemote = false;
    this.options.onClearSearch?.();
  }

  public setSearchQuery(value: string): void {
    this.searchQuery = value;
    this.cancelDebounce();
    const trimmed = value.trim();

    if (!trimmed) {
      this.searchGeneration++;
      this.remoteSessions = [];
      this.remoteCursor = null;
      this.hasMoreRemote = false;
      this.isLoadingRemote = false;
      this.options.onClearSearch?.();
      return;
    }

    const currentGen = ++this.searchGeneration;
    const debounceMs = this.options.debounceMs ?? 250;

    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      if (!this.isOpen || this.searchGeneration !== currentGen) {
        return;
      }
      this.options.onSearch?.(trimmed);
    }, debounceMs);
  }

  public cancelDebounce(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  public setRemoteResults(
    page: {
      items?: FilesystemClosedSession[];
      nextCursor?: string | null;
    },
    generation: number,
  ): boolean {
    if (!this.isOpen || this.searchGeneration !== generation) {
      return false;
    }
    if (Array.isArray(page.items)) {
      this.remoteSessions = page.items;
      this.remoteCursor = page.nextCursor ?? null;
      this.hasMoreRemote = Boolean(page.nextCursor);
    }
    this.isLoadingRemote = false;
    return true;
  }

  public appendRemoteResults(
    page: {
      items?: FilesystemClosedSession[];
      nextCursor?: string | null;
    },
    generation: number,
  ): boolean {
    if (!this.isOpen || this.searchGeneration !== generation) {
      return false;
    }
    if (Array.isArray(page.items)) {
      const seen = new Set(this.remoteSessions.map((s) => s.sessionId));
      const additions = page.items.filter((s) => !seen.has(s.sessionId));
      this.remoteSessions = [...this.remoteSessions, ...additions];
      this.remoteCursor = page.nextCursor ?? null;
      this.hasMoreRemote = Boolean(page.nextCursor);
    }
    this.isLoadingRemote = false;
    return true;
  }

  public setIsLoadingRemote(loading: boolean, generation?: number): boolean {
    if (generation !== undefined && (this.searchGeneration !== generation || !this.isOpen)) {
      return false;
    }
    this.isLoadingRemote = loading;
    return true;
  }

  public dispose(): void {
    this.cancelDebounce();
    this.searchGeneration++;
    this.isOpen = false;
  }
}
