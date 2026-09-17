import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";

export type FilesystemStreamState = "connecting" | "live" | "stale";
export type FilesystemRegionStatus = "loading" | "ready" | "refreshing" | "error" | "stale";

export const DEFAULT_STALE_THRESHOLD_MS = 30_000;

/**
 * Maximum acceptable future clock skew (5 seconds).
 * Timestamps further in the future than this tolerance are treated as untrusted/invalid.
 */
export const MAX_FUTURE_TELEMETRY_SKEW_MS = 5_000;

export function formatUpdateAge(ageMs: number): string {
  if (typeof ageMs !== "number" || isNaN(ageMs) || ageMs < 0) return "Just now";
  if (ageMs < 3_000) return "Just now";
  if (ageMs < 60_000) return `${Math.floor(ageMs / 1_000)}s ago`;
  if (ageMs < 3_600_000) return `${Math.floor(ageMs / 60_000)}m ago`;
  return `${Math.floor(ageMs / 3_600_000)}h ago`;
}

/**
 * Pure extraction function that derives the latest authoritative telemetry timestamp
 * from a snapshot's active and recent closed sessions.
 *
 * Contributing fields:
 * - active session `cwdState.observedAt`
 * - retained/recent session `cwdState.observedAt`
 * - `lifecycle.closedAt` where it represents newer authoritative session telemetry
 *
 * NOTE: Server snapshot-build time (`generatedAt`) is deliberately NOT counted as telemetry.
 */
export function deriveLatestTelemetryAt(snapshot: {
  sessions?: Array<{ cwdState?: { observedAt?: string | null } | null }> | null;
  recentClosedSessions?: Array<{
    cwdState?: { observedAt?: string | null } | null;
    lifecycle?: { closedAt?: string | null } | null;
  }> | null;
} | null | undefined): string | null {
  if (!snapshot) return null;
  let maxMs = -Infinity;
  let latestIso: string | null = null;

  const consider = (iso: string | null | undefined) => {
    if (typeof iso !== "string" || !iso.trim()) return;
    const ms = Date.parse(iso);
    if (!Number.isNaN(ms) && ms > maxMs) {
      maxMs = ms;
      latestIso = iso;
    }
  };

  if (Array.isArray(snapshot.sessions)) {
    for (const session of snapshot.sessions) {
      consider(session?.cwdState?.observedAt);
    }
  }

  if (Array.isArray(snapshot.recentClosedSessions)) {
    for (const session of snapshot.recentClosedSessions) {
      consider(session?.cwdState?.observedAt);
      consider(session?.lifecycle?.closedAt);
    }
  }

  return latestIso;
}

export type TelemetryStatus = "none" | "valid" | "invalid" | "future_skew";

export interface TelemetryAgeMetrics {
  /** The authoritative telemetry observation timestamp ISO string, or null if absent. */
  telemetryAt: string | null;
  /**
   * Age in milliseconds since latest telemetry observation.
   * Defined only when telemetryStatus === "valid". Null otherwise.
   */
  telemetryAgeMs: number | null;
  /** Categorized status of the telemetry observation timestamp. */
  telemetryStatus: TelemetryStatus;
  /**
   * Client-local age in milliseconds since the accepted snapshot was received.
   * Derived from snapshotReceivedAtMs, never generatedAt.
   */
  snapshotReceiptAgeMs: number;
  /**
   * Legacy alias for snapshotReceiptAgeMs for backward compatibility.
   */
  retrievalAgeMs: number;
  /**
   * Server generation age in milliseconds, derived from snapshot.generatedAt.
   * For ordering and truthful display only.
   */
  serverGenerationAgeMs: number;
  /** True when the snapshot contains active or recent closed sessions. */
  hasTelemetry: boolean;
}

export interface CalculateTelemetryAgeParams {
  snapshot: FilesystemTopologySnapshot | null | undefined;
  /**
   * Client timestamp (ms epoch) when the accepted snapshot was received.
   * If null/omitted, falls back to snapshot.generatedAt parsed ms or now.
   */
  snapshotReceivedAtMs?: number | null;
  /** Injected clock for deterministic testing (defaults to Date.now()). */
  now?: number;
  /** Maximum acceptable future clock skew tolerance in ms (defaults to 5,000ms). */
  futureSkewToleranceMs?: number;
}

/**
 * Calculates separate telemetry, client receipt, and server generation ages for a topology snapshot,
 * enforcing a bounded future clock-skew policy.
 */
export function calculateTelemetryAge(params: CalculateTelemetryAgeParams): TelemetryAgeMetrics {
  const {
    snapshot,
    snapshotReceivedAtMs,
    now = Date.now(),
    futureSkewToleranceMs = MAX_FUTURE_TELEMETRY_SKEW_MS,
  } = params;

  if (!snapshot) {
    return {
      telemetryAt: null,
      telemetryAgeMs: null,
      telemetryStatus: "none",
      snapshotReceiptAgeMs: 0,
      retrievalAgeMs: 0,
      serverGenerationAgeMs: 0,
      hasTelemetry: false,
    };
  }

  // 1. Server generation age (for ordering and display)
  const serverGenMs = Date.parse(snapshot.generatedAt);
  const serverGenerationAgeMs = Number.isNaN(serverGenMs)
    ? 0
    : Math.max(0, now - Math.min(serverGenMs, now));

  // 2. Client snapshot receipt age: derived from snapshotReceivedAtMs!
  const effectiveReceiptMs = typeof snapshotReceivedAtMs === "number" && Number.isFinite(snapshotReceivedAtMs)
    ? snapshotReceivedAtMs
    : (Number.isNaN(serverGenMs) ? now : serverGenMs);
  const snapshotReceiptAgeMs = Math.max(0, now - Math.min(effectiveReceiptMs, now));

  // 3. Telemetry timestamp resolution
  const telemetryAt = snapshot.latestTelemetryAt !== undefined
    ? snapshot.latestTelemetryAt
    : deriveLatestTelemetryAt(snapshot);

  const hasSessions = Boolean(
    (snapshot.sessions && snapshot.sessions.length > 0) ||
    (snapshot.recentClosedSessions && snapshot.recentClosedSessions.length > 0),
  );

  if (!hasSessions) {
    return {
      telemetryAt,
      telemetryAgeMs: null,
      telemetryStatus: "none",
      snapshotReceiptAgeMs,
      retrievalAgeMs: snapshotReceiptAgeMs,
      serverGenerationAgeMs,
      hasTelemetry: false,
    };
  }

  // Sessions exist, evaluate telemetry timestamp
  if (typeof telemetryAt !== "string" || !telemetryAt.trim()) {
    return {
      telemetryAt: null,
      telemetryAgeMs: null,
      telemetryStatus: "invalid",
      snapshotReceiptAgeMs,
      retrievalAgeMs: snapshotReceiptAgeMs,
      serverGenerationAgeMs,
      hasTelemetry: true,
    };
  }

  const parsedTelemetryMs = Date.parse(telemetryAt);
  if (Number.isNaN(parsedTelemetryMs)) {
    return {
      telemetryAt,
      telemetryAgeMs: null,
      telemetryStatus: "invalid",
      snapshotReceiptAgeMs,
      retrievalAgeMs: snapshotReceiptAgeMs,
      serverGenerationAgeMs,
      hasTelemetry: true,
    };
  }

  // Check future skew
  if (parsedTelemetryMs > now) {
    const futureSkewMs = parsedTelemetryMs - now;
    if (futureSkewMs <= futureSkewToleranceMs) {
      // Within tolerance: normalize age to 0, treated as valid
      return {
        telemetryAt,
        telemetryAgeMs: 0,
        telemetryStatus: "valid",
        snapshotReceiptAgeMs,
        retrievalAgeMs: snapshotReceiptAgeMs,
        serverGenerationAgeMs,
        hasTelemetry: true,
      };
    }

    // Beyond tolerance: excessive clock skew! Untrusted / fail-closed
    return {
      telemetryAt,
      telemetryAgeMs: null,
      telemetryStatus: "future_skew",
      snapshotReceiptAgeMs,
      retrievalAgeMs: snapshotReceiptAgeMs,
      serverGenerationAgeMs,
      hasTelemetry: true,
    };
  }

  // Valid past/current telemetry
  const telemetryAgeMs = Math.max(0, now - parsedTelemetryMs);
  return {
    telemetryAt,
    telemetryAgeMs,
    telemetryStatus: "valid",
    snapshotReceiptAgeMs,
    retrievalAgeMs: snapshotReceiptAgeMs,
    serverGenerationAgeMs,
    hasTelemetry: true,
  };
}

export type FreshnessClassification = "fresh" | "stale" | "degraded" | "offline";

export interface FreshnessState {
  classification: FreshnessClassification;
  label: string;
  detail: string;
  badgeClass: string;
  dotClass: string;
  isDegraded: boolean;
  isStale: boolean;
  telemetryAgeMs: number | null;
  snapshotReceiptAgeMs: number;
  /** Legacy alias for snapshotReceiptAgeMs. */
  retrievalAgeMs: number;
  telemetryStatus: TelemetryStatus;
}

export interface FreshnessStateParams {
  telemetryAgeMs?: number | null;
  telemetryStatus?: TelemetryStatus;
  snapshotReceiptAgeMs?: number;
  retrievalAgeMs?: number;
  lastUpdateAgeMs?: number;
  hasTelemetry?: boolean;
  staleThresholdMs?: number;
  streamState: FilesystemStreamState;
  regionStatus: FilesystemRegionStatus;
  hasSnapshot: boolean;
}

export function getFreshnessState(params: FreshnessStateParams): FreshnessState {
  const {
    lastUpdateAgeMs,
    staleThresholdMs = DEFAULT_STALE_THRESHOLD_MS,
    streamState,
    regionStatus,
    hasSnapshot,
  } = params;

  // Resolve snapshot receipt age: snapshotReceiptAgeMs -> retrievalAgeMs -> lastUpdateAgeMs -> 0
  const effectiveReceiptAgeMs = Math.max(
    0,
    params.snapshotReceiptAgeMs ?? params.retrievalAgeMs ?? lastUpdateAgeMs ?? 0,
  );

  // Resolve telemetry existence
  const hasTelemetry = params.hasTelemetry !== undefined
    ? params.hasTelemetry
    : (params.telemetryAgeMs !== undefined ? params.telemetryAgeMs !== null : lastUpdateAgeMs !== undefined);

  // Resolve telemetry status
  let telemetryStatus: TelemetryStatus;
  if (params.telemetryStatus !== undefined) {
    telemetryStatus = params.telemetryStatus;
  } else if (!hasTelemetry) {
    telemetryStatus = "none";
  } else if (params.telemetryAgeMs !== null && params.telemetryAgeMs !== undefined && !Number.isNaN(params.telemetryAgeMs)) {
    telemetryStatus = "valid";
  } else if (lastUpdateAgeMs !== undefined) {
    telemetryStatus = "valid";
  } else {
    telemetryStatus = "invalid";
  }

  // Resolve telemetry age (only valid when status === "valid")
  const rawTelemetryAgeMs = telemetryStatus === "valid"
    ? (params.telemetryAgeMs !== undefined ? params.telemetryAgeMs : (lastUpdateAgeMs !== undefined ? lastUpdateAgeMs : null))
    : null;
  const effectiveTelemetryAgeMs = rawTelemetryAgeMs !== null && !Number.isNaN(rawTelemetryAgeMs)
    ? Math.max(0, rawTelemetryAgeMs)
    : null;

  if (!hasSnapshot) {
    if (regionStatus === "loading" || streamState === "connecting") {
      return {
        classification: "offline",
        label: "Connecting",
        detail: "Connecting to real-time filesystem stream...",
        badgeClass: "border-border bg-surface-subtle text-text-subtle",
        dotClass: "bg-text-subtle animate-pulse",
        isDegraded: false,
        isStale: false,
        telemetryAgeMs: null,
        snapshotReceiptAgeMs: effectiveReceiptAgeMs,
        retrievalAgeMs: effectiveReceiptAgeMs,
        telemetryStatus,
      };
    }
    return {
      classification: "offline",
      label: "Offline",
      detail: "Topology stream unavailable. No valid snapshot loaded.",
      badgeClass: "border-danger-border bg-danger-subtle text-danger",
      dotClass: "bg-danger",
      isDegraded: true,
      isStale: true,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus,
    };
  }

  const isTransportLive = streamState === "live" && regionStatus !== "error" && regionStatus !== "stale";

  // Retained snapshot with degraded transport or error
  if (!isTransportLive) {
    const isStale = telemetryStatus === "valid" && effectiveTelemetryAgeMs !== null
      ? effectiveTelemetryAgeMs > staleThresholdMs
      : telemetryStatus !== "none";

    return {
      classification: "degraded",
      label: "Degraded",
      detail: `Reconnecting transport — displaying retained snapshot from ${formatUpdateAge(effectiveReceiptAgeMs)}.`,
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning animate-pulse",
      isDegraded: true,
      isStale,
      telemetryAgeMs: effectiveTelemetryAgeMs,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus,
    };
  }

  // Transport is live:
  // Case 1: Empty snapshot (no session activity)
  if (telemetryStatus === "none") {
    return {
      classification: "fresh",
      label: "Live · No activity",
      detail: "Live stream active · no session activity recorded.",
      badgeClass: "border-border bg-surface-subtle text-text-muted",
      dotClass: "bg-success",
      isDegraded: false,
      isStale: false,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus: "none",
    };
  }

  // Case 2: Excessive future clock skew (untrusted)
  if (telemetryStatus === "future_skew") {
    return {
      classification: "stale",
      label: "Stale",
      detail: "Connected, but telemetry timestamp is in the future beyond acceptable skew tolerance (clock skew detected).",
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning",
      isDegraded: false,
      isStale: true,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus: "future_skew",
    };
  }

  // Case 3: Missing/invalid telemetry timestamps with existing sessions
  if (telemetryStatus === "invalid" || effectiveTelemetryAgeMs === null) {
    return {
      classification: "stale",
      label: "Stale",
      detail: "Connected, but telemetry timestamps are unavailable or invalid.",
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning",
      isDegraded: false,
      isStale: true,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus: "invalid",
    };
  }

  // Case 4: Telemetry age exceeds stale threshold
  if (effectiveTelemetryAgeMs > staleThresholdMs) {
    return {
      classification: "stale",
      label: "Stale",
      detail: `Connected, but no new telemetry for ${formatUpdateAge(effectiveTelemetryAgeMs)} (threshold: ${Math.round(staleThresholdMs / 1000)}s).`,
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning",
      isDegraded: false,
      isStale: true,
      telemetryAgeMs: effectiveTelemetryAgeMs,
      snapshotReceiptAgeMs: effectiveReceiptAgeMs,
      retrievalAgeMs: effectiveReceiptAgeMs,
      telemetryStatus: "valid",
    };
  }

  // Case 5: Live transport with fresh telemetry
  return {
    classification: "fresh",
    label: "Live & Fresh",
    detail: `Live stream active · telemetry observed ${formatUpdateAge(effectiveTelemetryAgeMs)}.`,
    badgeClass: "border-success-border bg-success-subtle text-success",
    dotClass: "bg-success",
    isDegraded: false,
    isStale: false,
    telemetryAgeMs: effectiveTelemetryAgeMs,
    snapshotReceiptAgeMs: effectiveReceiptAgeMs,
    retrievalAgeMs: effectiveReceiptAgeMs,
    telemetryStatus: "valid",
  };
}
