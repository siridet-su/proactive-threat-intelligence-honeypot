import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import type { RegionStatus } from "@/components/ui/RegionState";
import { isSnapshot } from "./filesystemUtils";

export type RefreshStatus = "idle" | "refreshing" | "error";

export interface RefreshLifecycleOptions {
  fetchSnapshot?: (url: string, init?: RequestInit) => Promise<Response>;
  refreshUrl?: string;
  hasSnapshot: () => boolean;
  applySnapshot: (snapshot: FilesystemTopologySnapshot) => boolean;
  onRegionStatus?: (status: RegionStatus) => void;
  onRefreshStatus?: (status: RefreshStatus, error: Error | null) => void;
}

/**
 * Manages manual HTTP snapshot refresh requests with monotonic generation scoping,
 * abort handling, and authoritative separation of HTTP retrieval errors from transport health.
 *
 * Guarantees:
 * 1. Monotonically increasing generation scopes every refresh invocation.
 * 2. In-flight refresh requests are aborted via AbortController when a new refresh begins or on disposal.
 * 3. A failed HTTP refresh preserves the currently accepted snapshot and does NOT downgrade
 *    a live SSE transport into Degraded or Offline.
 * 4. Stale responses (success, error, or aborted) from superseded generations are discarded.
 * 5. Out-of-order snapshots rejected by SnapshotIngestionCoordinator do not mutate state or trigger errors.
 */
export class FilesystemRefreshLifecycleManager {
  private disposed = false;
  private currentGeneration = 0;
  private activeAbortController: AbortController | null = null;
  private refreshStatus: RefreshStatus = "idle";
  private refreshError: Error | null = null;

  constructor(private options: RefreshLifecycleOptions) {}

  public async refresh(): Promise<boolean> {
    if (this.disposed) return false;

    this.currentGeneration++;
    const generation = this.currentGeneration;

    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = null;
    }

    const controller = new AbortController();
    this.activeAbortController = controller;

    this.refreshStatus = "refreshing";
    this.refreshError = null;
    this.options.onRefreshStatus?.("refreshing", null);

    const hasSnap = this.options.hasSnapshot();
    if (hasSnap) {
      this.options.onRegionStatus?.("refreshing");
    } else {
      this.options.onRegionStatus?.("loading");
    }

    const fetchFn = this.options.fetchSnapshot ?? ((u, init) => fetch(u, { cache: "no-store", ...init }));
    const url = this.options.refreshUrl ?? "/api/filesystem-topology";

    try {
      const response = await fetchFn(url, { signal: controller.signal });
      if (this.disposed || this.currentGeneration !== generation) {
        return false;
      }
      if (!response.ok) {
        throw new Error(`Topology request failed with HTTP ${response.status}`);
      }
      const data: unknown = await response.json();
      if (this.disposed || this.currentGeneration !== generation) {
        return false;
      }
      if (!isSnapshot(data)) {
        throw new Error("Topology response unavailable: invalid snapshot schema");
      }

      const accepted = this.options.applySnapshot(data);
      if (accepted) {
        this.refreshStatus = "idle";
        this.refreshError = null;
        this.options.onRefreshStatus?.("idle", null);
        this.options.onRegionStatus?.("ready");
        return true;
      } else {
        // Snapshot was rejected by coordinator (e.g. out of order).
        // It must NOT overwrite the current snapshot, reset receipt time, or trigger false degradation.
        this.refreshStatus = "idle";
        this.refreshError = null;
        this.options.onRefreshStatus?.("idle", null);
        if (this.options.hasSnapshot()) {
          this.options.onRegionStatus?.("ready");
        }
        return false;
      }
    } catch (err: unknown) {
      if (controller.signal.aborted || this.disposed || this.currentGeneration !== generation) {
        return false;
      }

      const error = err instanceof Error ? err : new Error(String(err));
      this.refreshStatus = "error";
      this.refreshError = error;
      this.options.onRefreshStatus?.("error", error);

      // Separate HTTP retrieval error from transport/snapshot state:
      if (this.options.hasSnapshot()) {
        // Retained snapshot remains ready to display without downgrading live stream
        this.options.onRegionStatus?.("ready");
      } else {
        this.options.onRegionStatus?.("error");
      }
      return false;
    } finally {
      if (this.activeAbortController === controller) {
        this.activeAbortController = null;
      }
    }
  }

  public dispose(): void {
    this.disposed = true;
    this.currentGeneration++;
    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = null;
    }
  }

  public getCurrentGeneration(): number {
    return this.currentGeneration;
  }

  public getRefreshStatus(): RefreshStatus {
    return this.refreshStatus;
  }

  public getRefreshError(): Error | null {
    return this.refreshError;
  }

  public isDisposed(): boolean {
    return this.disposed;
  }
}
