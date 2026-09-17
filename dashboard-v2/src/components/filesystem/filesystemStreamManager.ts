import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import type { RegionStatus } from "@/components/ui/RegionState";
import { isSnapshot, type StreamState } from "./filesystemUtils";

export interface StreamLifecycleOptions {
  streamUrl?: string;
  fallbackUrl?: string;
  createEventSource?: (url: string) => EventSource;
  fetchFallback?: (url: string) => Promise<Response>;
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
 * 1. Connecting -> live transitions never tear down or reconnect the active stream.
 * 2. Ordinary parent/component rerenders never recreate or re-register listeners.
 * 3. Connection retry timers are bounded (5s) and cleaned up strictly on disposal.
 * 4. Explicit reconnect() cleanly closes prior connection before starting a new one.
 */
export class FilesystemStreamLifecycleManager {
  private disposed = false;
  private source: EventSource | null = null;
  private retryTimeout: ReturnType<typeof setTimeout> | null = null;
  private connectionCount = 0;
  private cleanupCount = 0;

  constructor(private options: StreamLifecycleOptions) {}

  public connect(): void {
    if (this.disposed) return;

    if (this.retryTimeout !== null) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
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
      try {
        const message: unknown = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
        const data = (message as { data?: unknown }).data;
        if (!isSnapshot(data) || this.disposed) return;
        this.options.onSnapshot(data);
        this.options.onStreamState("live");
      } catch {
        /* retain last valid topology */
      }
    };

    source.addEventListener("snapshot", onMessage as EventListener);
    source.addEventListener("topology.update", onMessage as EventListener);

    source.onopen = () => {
      if (this.disposed) return;
      this.options.onHydrated();
      this.options.onStreamState("live");
    };

    source.onerror = () => {
      if (this.disposed || this.source === null) return;
      this.options.onHydrated();
      this.options.onStreamState("stale");
      this.cleanupCount++;
      source.close();
      this.source = null;
      void this.fetchFallbackSnapshot();
      this.retryTimeout = setTimeout(() => {
        if (!this.disposed) {
          this.connect();
        }
      }, 5_000);
    };
  }

  private async fetchFallbackSnapshot(): Promise<void> {
    if (this.disposed) return;
    const fetchFn = this.options.fetchFallback ?? ((u) => fetch(u, { cache: "no-store" }));
    const fallbackUrl = this.options.fallbackUrl ?? "/api/filesystem-topology";
    try {
      const response = await fetchFn(fallbackUrl);
      if (!response.ok) throw new Error("Fallback request failed");
      const data: unknown = await response.json();
      if (!isSnapshot(data) || this.disposed) return;
      this.options.onSnapshot(data);
    } catch {
      if (!this.disposed && this.options.onRegionStatus) {
        this.options.onRegionStatus((curr) => (curr === "ready" ? "stale" : "error"));
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
    if (this.retryTimeout !== null) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }
    if (this.source) {
      this.cleanupCount++;
      this.source.close();
      this.source = null;
    }
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
