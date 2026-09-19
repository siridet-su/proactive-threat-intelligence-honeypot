import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import type { RegionStatus } from "@/components/ui/RegionState";
import { isSnapshot, type StreamState } from "./filesystemUtils";

export interface StreamLifecycleOptions {
  streamUrl?: string;
  fallbackUrl?: string;
  createEventSource?: (url: string) => EventSource;
  fetchFallback?: (url: string, init?: RequestInit) => Promise<Response>;
  onSnapshot: (snapshot: FilesystemTopologySnapshot) => void;
  onStreamState: (state: StreamState) => void;
  onRegionStatus?: (statusUpdater: (current: RegionStatus) => RegionStatus) => void;
  onHydrated: () => void;
}

/**
 * Encapsulates the SSE stream connection lifecycle, message listeners, reconnection,
 * and HTTP fallback fetching for the filesystem topology.
 *
 * Guarantees:
 * 1. Monotonically incrementing generation scopes every connection attempt.
 * 2. Stale onerror/onmessage/onopen callbacks from superseded connections are discarded.
 * 3. In-flight fallback requests are aborted on reconnection or disposal via AbortController.
 * 4. At most one active EventSource exists at any time.
 * 5. Ordinary parent/component rerenders never recreate or re-register listeners.
 */
export class FilesystemStreamLifecycleManager {
  private disposed = false;
  private currentGeneration = 0;
  private source: EventSource | null = null;
  private retryTimeout: ReturnType<typeof setTimeout> | null = null;
  private fallbackAbortController: AbortController | null = null;
  private connectionCount = 0;
  private cleanupCount = 0;

  constructor(private options: StreamLifecycleOptions) {}

  public connect(): void {
    if (this.disposed) return;

    this.currentGeneration++;
    const generation = this.currentGeneration;

    if (this.retryTimeout !== null) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }

    if (this.fallbackAbortController) {
      this.fallbackAbortController.abort();
      this.fallbackAbortController = null;
    }

    if (this.source) {
      this.cleanupCount++;
      this.source.close();
      this.source = null;
    }

    this.options.onStreamState("connecting");
    this.connectionCount++;

    const url = this.options.streamUrl ?? "/api/filesystem-topology/stream";
    const source = this.options.createEventSource
      ? this.options.createEventSource(url)
      : new EventSource(url);
    this.source = source;

    const onMessage = (event: MessageEvent<string>) => {
      if (this.disposed || this.currentGeneration !== generation || this.source !== source) {
        return;
      }
      try {
        const message: unknown = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
        const data = (message as { data?: unknown }).data;
        if (!isSnapshot(data)) return;
        this.options.onSnapshot(data);
        this.options.onStreamState("live");
      } catch {
        /* retain last valid topology */
      }
    };

    source.addEventListener("snapshot", onMessage as EventListener);
    source.addEventListener("topology.update", onMessage as EventListener);

    source.onopen = () => {
      if (this.disposed || this.currentGeneration !== generation || this.source !== source) {
        return;
      }
      this.options.onHydrated();
      this.options.onStreamState("live");
    };

    source.onerror = () => {
      if (this.disposed || this.currentGeneration !== generation || this.source !== source) {
        return;
      }
      this.options.onHydrated();
      this.options.onStreamState("stale");
      this.cleanupCount++;
      source.close();
      this.source = null;
      void this.fetchFallbackSnapshot(generation);
      this.retryTimeout = setTimeout(() => {
        if (!this.disposed && this.currentGeneration === generation) {
          this.connect();
        }
      }, 5_000);
    };
  }

  private async fetchFallbackSnapshot(generation: number): Promise<void> {
    if (this.disposed || this.currentGeneration !== generation) return;

    if (this.fallbackAbortController) {
      this.fallbackAbortController.abort();
    }
    const abortController = new AbortController();
    this.fallbackAbortController = abortController;

    const fetchFn = this.options.fetchFallback ?? ((u, init) => fetch(u, { cache: "no-store", ...init }));
    const fallbackUrl = this.options.fallbackUrl ?? "/api/filesystem-topology";
    try {
      const response = await fetchFn(fallbackUrl, { signal: abortController.signal });
      if (this.disposed || this.currentGeneration !== generation) return;
      if (!response.ok) throw new Error("Fallback request failed");
      const data: unknown = await response.json();
      if (this.disposed || this.currentGeneration !== generation) return;
      if (!isSnapshot(data)) return;
      this.options.onSnapshot(data);
    } catch {
      if (abortController.signal.aborted || this.disposed || this.currentGeneration !== generation) {
        return;
      }
      if (this.options.onRegionStatus) {
        this.options.onRegionStatus((curr) => (curr === "ready" ? "stale" : "error"));
      }
    } finally {
      if (this.fallbackAbortController === abortController) {
        this.fallbackAbortController = null;
      }
    }
  }

  public reconnect(): void {
    if (!this.disposed) {
      this.connect();
    }
  }

  public dispose(): void {
    this.disposed = true;
    this.currentGeneration++;
    if (this.retryTimeout !== null) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }
    if (this.fallbackAbortController) {
      this.fallbackAbortController.abort();
      this.fallbackAbortController = null;
    }
    if (this.source) {
      this.cleanupCount++;
      this.source.close();
      this.source = null;
    }
  }

  public getCurrentGeneration(): number {
    return this.currentGeneration;
  }

  public getConnectionCount(): number {
    return this.connectionCount;
  }

  public getCleanupCount(): number {
    return this.cleanupCount;
  }

  public isDisposed(): boolean {
    return this.disposed;
  }

  public getActiveSource(): EventSource | null {
    return this.source;
  }
}
