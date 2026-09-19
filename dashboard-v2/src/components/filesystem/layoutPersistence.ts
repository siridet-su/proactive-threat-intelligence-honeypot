"use client";

import { unrestrictedNodeCoordinate } from "./useTopologyArrange";
import type { LabelPosition } from "./filesystemUtils";

export const LAYOUT_SCHEMA_VERSION = 1;
export const MAX_STORED_AUDIT_LAYOUTS = 30;
export const AUDIT_LAYOUT_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

export const LIVE_LABEL_STORAGE_KEY = "pti-label-layout-live";
export const LIVE_NODE_STORAGE_KEY = "pti-node-layout-live";
export const AUDIT_LABEL_KEY_PREFIX = "pti-label-layout-audit-";
export const AUDIT_NODE_KEY_PREFIX = "pti-node-layout-audit-";

export interface StoredLayoutEnvelope {
  version: number;
  updatedAt: number;
  positions: Record<string, LabelPosition>;
}

/**
 * Safely access window.localStorage without throwing when storage is blocked,
 * disabled, or restricted (e.g. SecurityError in private browsing or iframe).
 */
export function getLocalStorageSafe(): Storage | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage;
    }
    if (typeof process !== "undefined" && process.env.VITEST && typeof localStorage !== "undefined") {
      return localStorage;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Generate isolated, collision-free storage keys for live and audit modes.
 */
export function getLayoutStorageKeys(
  isAuditMode: boolean,
  sessionId?: string | null,
): { labelStorageKey: string; nodeStorageKey: string } {
  if (!isAuditMode) {
    return {
      labelStorageKey: LIVE_LABEL_STORAGE_KEY,
      nodeStorageKey: LIVE_NODE_STORAGE_KEY,
    };
  }

  const safeSessionId = sessionId ? encodeURIComponent(sessionId) : "default";
  return {
    labelStorageKey: `${AUDIT_LABEL_KEY_PREFIX}${safeSessionId}`,
    nodeStorageKey: `${AUDIT_NODE_KEY_PREFIX}${safeSessionId}`,
  };
}

/**
 * Parse raw storage content, supporting both legacy unversioned format and
 * schema version 1 envelopes. Validates finite numbers, filters malformed objects,
 * and clamps coordinates within workspace boundaries.
 */
export function parseAndValidateLayout(raw: string | null): {
  positions: Record<string, LabelPosition>;
  version: number;
  updatedAt: number;
} {
  if (!raw) {
    return { positions: {}, version: LAYOUT_SCHEMA_VERSION, updatedAt: 0 };
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { positions: {}, version: LAYOUT_SCHEMA_VERSION, updatedAt: 0 };
    }

    let version = 0;
    let updatedAt = 0;
    let candidatePositions: unknown = parsed;

    const record = parsed as Record<string, unknown>;
    if (typeof record.version === "number" && record.positions && typeof record.positions === "object") {
      version = record.version;
      updatedAt = typeof record.updatedAt === "number" && Number.isFinite(record.updatedAt) ? record.updatedAt : 0;
      candidatePositions = record.positions;
    }

    if (!candidatePositions || typeof candidatePositions !== "object" || Array.isArray(candidatePositions)) {
      return { positions: {}, version, updatedAt };
    }

    const validated: Record<string, LabelPosition> = {};
    for (const [key, val] of Object.entries(candidatePositions)) {
      if (!val || typeof val !== "object" || Array.isArray(val)) continue;
      const candidate = val as Partial<LabelPosition>;
      if (
        typeof candidate.x === "number" &&
        Number.isFinite(candidate.x) &&
        typeof candidate.y === "number" &&
        Number.isFinite(candidate.y)
      ) {
        validated[key] = {
          x: unrestrictedNodeCoordinate(candidate.x),
          y: unrestrictedNodeCoordinate(candidate.y),
        };
      }
    }

    return { positions: validated, version, updatedAt };
  } catch {
    // Malformed JSON or unexpected parse error
    return { positions: {}, version: LAYOUT_SCHEMA_VERSION, updatedAt: 0 };
  }
}

/**
 * Prune stale or excess audit layout keys from localStorage to prevent quota exhaustion.
 * Live layout keys are never pruned.
 */
export function pruneStaleAuditLayouts(options?: {
  maxEntries?: number;
  maxAgeMs?: number;
  retainKeys?: string[];
  now?: number;
}): number {
  const storage = getLocalStorageSafe();
  if (!storage) return 0;

  const maxEntries = options?.maxEntries ?? MAX_STORED_AUDIT_LAYOUTS;
  const maxAgeMs = options?.maxAgeMs ?? AUDIT_LAYOUT_MAX_AGE_MS;
  const retainKeys = new Set(options?.retainKeys ?? []);
  const now = options?.now ?? Date.now();

  const auditEntries: Array<{ key: string; updatedAt: number }> = [];

  try {
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (!key) continue;
      if (key.startsWith(AUDIT_LABEL_KEY_PREFIX) || key.startsWith(AUDIT_NODE_KEY_PREFIX)) {
        if (retainKeys.has(key)) continue;

        const raw = storage.getItem(key);
        const { updatedAt } = parseAndValidateLayout(raw);
        auditEntries.push({ key, updatedAt });
      }
    }
  } catch {
    return 0;
  }

  let prunedCount = 0;
  const remainingEntries: Array<{ key: string; updatedAt: number }> = [];

  // Phase 1: Prune by age
  for (const entry of auditEntries) {
    if (entry.updatedAt > 0 && now - entry.updatedAt > maxAgeMs) {
      try {
        storage.removeItem(entry.key);
        prunedCount++;
      } catch {
        // Ignore removal error
      }
    } else {
      remainingEntries.push(entry);
    }
  }

  // Phase 2: Prune excess if still over maxEntries
  if (remainingEntries.length > maxEntries) {
    // Sort oldest first (0 updatedAt considered oldest)
    remainingEntries.sort((a, b) => a.updatedAt - b.updatedAt);
    const removeCount = remainingEntries.length - maxEntries;
    for (let i = 0; i < removeCount; i++) {
      try {
        storage.removeItem(remainingEntries[i].key);
        prunedCount++;
      } catch {
        // Ignore removal error
      }
    }
  }

  return prunedCount;
}

/**
 * Load layout from localStorage with schema validation, coordinate bounds checking,
 * and automatic migration of legacy unversioned payloads.
 */
export function loadLayoutFromStorage(storageKey: string): Record<string, LabelPosition> {
  const storage = getLocalStorageSafe();
  if (!storage) return {};

  try {
    const raw = storage.getItem(storageKey);
    const { positions, version } = parseAndValidateLayout(raw);

    // If loaded legacy version 0 and has positions, upgrade to version 1 in background
    if (version === 0 && Object.keys(positions).length > 0) {
      saveLayoutToStorage(storageKey, positions);
    }

    return positions;
  } catch {
    return {};
  }
}

/**
 * Save layout to localStorage inside a versioned envelope.
 * Safely handles quota exhaustion by pruning stale audit entries and retrying.
 */
export function saveLayoutToStorage(storageKey: string, positions: Record<string, LabelPosition>): boolean {
  const storage = getLocalStorageSafe();
  if (!storage) return false;

  try {
    if (Object.keys(positions).length === 0) {
      storage.removeItem(storageKey);
      return true;
    }

    const envelope: StoredLayoutEnvelope = {
      version: LAYOUT_SCHEMA_VERSION,
      updatedAt: Date.now(),
      positions,
    };
    const serialized = JSON.stringify(envelope);

    try {
      storage.setItem(storageKey, serialized);
      return true;
    } catch {
      // Storage write failed (likely QuotaExceededError). Prune stale audit entries and retry once.
      pruneStaleAuditLayouts({ retainKeys: [storageKey] });
      try {
        storage.setItem(storageKey, serialized);
        return true;
      } catch {
        return false;
      }
    }
  } catch {
    return false;
  }
}

/**
 * Remove layout from localStorage safely without throwing.
 */
export function removeLayoutFromStorage(storageKey: string): boolean {
  const storage = getLocalStorageSafe();
  if (!storage) return false;
  try {
    storage.removeItem(storageKey);
    return true;
  } catch {
    return false;
  }
}
