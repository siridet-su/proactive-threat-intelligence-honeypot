import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  AUDIT_LABEL_KEY_PREFIX,
  AUDIT_LAYOUT_MAX_AGE_MS,
  AUDIT_NODE_KEY_PREFIX,
  getLayoutStorageKeys,
  LAYOUT_SCHEMA_VERSION,
  LIVE_LABEL_STORAGE_KEY,
  LIVE_NODE_STORAGE_KEY,
  loadLayoutFromStorage,
  MAX_STORED_AUDIT_LAYOUTS,
  parseAndValidateLayout,
  pruneStaleAuditLayouts,
  removeLayoutFromStorage,
  saveLayoutToStorage,
} from "../src/components/filesystem/layoutPersistence";

// Mock in-memory localStorage for tests
class MockStorage implements Storage {
  private store: Map<string, string> = new Map();

  get length(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  key(index: number): string | null {
    return Array.from(this.store.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

describe("layoutPersistence (FS-017)", () => {
  let mockStorage: MockStorage;

  beforeEach(() => {
    mockStorage = new MockStorage();
    vi.stubGlobal("localStorage", mockStorage);
  });

  describe("Isolation of Live and Audit keys", () => {
    it("returns distinct keys for live mode", () => {
      const keys = getLayoutStorageKeys(false);
      expect(keys.labelStorageKey).toBe(LIVE_LABEL_STORAGE_KEY);
      expect(keys.nodeStorageKey).toBe(LIVE_NODE_STORAGE_KEY);
    });

    it("returns scoped per-session keys for audit mode", () => {
      const keys = getLayoutStorageKeys(true, "session_456");
      expect(keys.labelStorageKey).toBe(`${AUDIT_LABEL_KEY_PREFIX}session_456`);
      expect(keys.nodeStorageKey).toBe(`${AUDIT_NODE_KEY_PREFIX}session_456`);
    });

    it("sanitizes special characters in session IDs", () => {
      const keys = getLayoutStorageKeys(true, "sess/123:test?foo=bar");
      expect(keys.labelStorageKey).toBe(`${AUDIT_LABEL_KEY_PREFIX}sess%2F123%3Atest%3Ffoo%3Dbar`);
    });

    it("falls back to default session if sessionId is missing or null", () => {
      const keys = getLayoutStorageKeys(true, null);
      expect(keys.labelStorageKey).toBe(`${AUDIT_LABEL_KEY_PREFIX}default`);
    });
  });

  describe("Blocked / Corrupt storage handling", () => {
    it("safely handles non-JSON corrupt storage data without throwing", () => {
      mockStorage.setItem("corrupt-key", "{invalid:json");
      const result = loadLayoutFromStorage("corrupt-key");
      expect(result).toEqual({});
    });

    it("safely handles non-object JSON values", () => {
      mockStorage.setItem("primitive-key", "42");
      expect(loadLayoutFromStorage("primitive-key")).toEqual({});

      mockStorage.setItem("array-key", "[1, 2, 3]");
      expect(loadLayoutFromStorage("array-key")).toEqual({});

      mockStorage.setItem("null-key", "null");
      expect(loadLayoutFromStorage("null-key")).toEqual({});
    });

    it("filters out malformed positions, nulls, and non-numeric coordinates", () => {
      const raw = JSON.stringify({
        "/valid": { x: 100, y: 200 },
        "/invalid-null": null,
        "/invalid-array": [10, 20],
        "/invalid-nan": { x: NaN, y: 50 },
        "/invalid-infinity": { x: 50, y: Infinity },
        "/invalid-string": { x: "100", y: 200 },
        "/missing-y": { x: 100 },
      });
      const { positions } = parseAndValidateLayout(raw);
      expect(positions).toEqual({
        "/valid": { x: 100, y: 200 },
      });
    });

    it("clamps out-of-bounds coordinates to NODE_WORKSPACE_LIMIT", () => {
      const raw = JSON.stringify({
        "/far-away": { x: 9999, y: -9999 },
      });
      const { positions } = parseAndValidateLayout(raw);
      expect(positions["/far-away"]).toEqual({ x: 400, y: -400 });
    });

    it("handles storage throwing SecurityError gracefully", () => {
      const throwingStorage = {
        getItem: () => {
          throw new DOMException("Access is denied", "SecurityError");
        },
        setItem: () => {
          throw new DOMException("Access is denied", "SecurityError");
        },
        removeItem: () => {
          throw new DOMException("Access is denied", "SecurityError");
        },
        length: 0,
        clear: () => {},
        key: () => null,
      };
      vi.stubGlobal("localStorage", throwingStorage);

      expect(loadLayoutFromStorage("any-key")).toEqual({});
      expect(saveLayoutToStorage("any-key", { test: { x: 10, y: 10 } })).toBe(false);
      expect(removeLayoutFromStorage("any-key")).toBe(false);
    });
  });

  describe("Version migration and serialization", () => {
    it("reads legacy unversioned layout and auto-migrates to version 1", () => {
      const legacyPayload = {
        "/etc": { x: 20, y: 30 },
        "/var": { x: 40, y: 50 },
      };
      mockStorage.setItem(LIVE_NODE_STORAGE_KEY, JSON.stringify(legacyPayload));

      const loaded = loadLayoutFromStorage(LIVE_NODE_STORAGE_KEY);
      expect(loaded).toEqual(legacyPayload);

      // Verify it was upgraded in storage to versioned envelope
      const rawAfter = mockStorage.getItem(LIVE_NODE_STORAGE_KEY);
      expect(rawAfter).toBeTruthy();
      const envelope = JSON.parse(rawAfter!);
      expect(envelope.version).toBe(LAYOUT_SCHEMA_VERSION);
      expect(envelope.updatedAt).toBeGreaterThan(0);
      expect(envelope.positions).toEqual(legacyPayload);
    });

    it("saves positions wrapped in versioned envelope", () => {
      const positions = {
        "192.168.1.100": { x: 15, y: 25 },
      };
      const ok = saveLayoutToStorage("test-key", positions);
      expect(ok).toBe(true);

      const raw = mockStorage.getItem("test-key");
      const envelope = JSON.parse(raw!);
      expect(envelope.version).toBe(LAYOUT_SCHEMA_VERSION);
      expect(envelope.positions).toEqual(positions);
    });

    it("removes storage entry when saving empty positions", () => {
      mockStorage.setItem("test-key", JSON.stringify({ version: 1, updatedAt: 123, positions: { a: { x: 1, y: 2 } } }));
      saveLayoutToStorage("test-key", {});
      expect(mockStorage.getItem("test-key")).toBeNull();
    });
  });

  describe("Stale audit entries pruning", () => {
    it("prunes audit layouts older than AUDIT_LAYOUT_MAX_AGE_MS", () => {
      const now = Date.now();
      const oldTime = now - (AUDIT_LAYOUT_MAX_AGE_MS + 1000); // 14 days + 1s old
      const freshTime = now - 1000;

      mockStorage.setItem(
        `${AUDIT_LABEL_KEY_PREFIX}stale-sess`,
        JSON.stringify({ version: 1, updatedAt: oldTime, positions: { ip: { x: 10, y: 10 } } }),
      );
      mockStorage.setItem(
        `${AUDIT_LABEL_KEY_PREFIX}fresh-sess`,
        JSON.stringify({ version: 1, updatedAt: freshTime, positions: { ip: { x: 20, y: 20 } } }),
      );

      const pruned = pruneStaleAuditLayouts({ now });
      expect(pruned).toBe(1);
      expect(mockStorage.getItem(`${AUDIT_LABEL_KEY_PREFIX}stale-sess`)).toBeNull();
      expect(mockStorage.getItem(`${AUDIT_LABEL_KEY_PREFIX}fresh-sess`)).toBeTruthy();
    });

    it("never prunes live layout keys even if old", () => {
      const oldTime = Date.now() - (AUDIT_LAYOUT_MAX_AGE_MS * 2);
      mockStorage.setItem(
        LIVE_LABEL_STORAGE_KEY,
        JSON.stringify({ version: 1, updatedAt: oldTime, positions: { ip: { x: 10, y: 10 } } }),
      );
      mockStorage.setItem(
        LIVE_NODE_STORAGE_KEY,
        JSON.stringify({ version: 1, updatedAt: oldTime, positions: { node: { x: 10, y: 10 } } }),
      );

      const pruned = pruneStaleAuditLayouts();
      expect(pruned).toBe(0);
      expect(mockStorage.getItem(LIVE_LABEL_STORAGE_KEY)).toBeTruthy();
      expect(mockStorage.getItem(LIVE_NODE_STORAGE_KEY)).toBeTruthy();
    });

    it("prunes oldest excess audit entries when exceeding MAX_STORED_AUDIT_LAYOUTS", () => {
      const now = Date.now();
      // Insert 35 audit entries
      for (let i = 0; i < 35; i++) {
        mockStorage.setItem(
          `${AUDIT_LABEL_KEY_PREFIX}sess-${i.toString().padStart(2, "0")}`,
          JSON.stringify({ version: 1, updatedAt: now - (35 - i) * 1000, positions: { a: { x: 1, y: 1 } } }),
        );
      }

      expect(mockStorage.length).toBe(35);
      const pruned = pruneStaleAuditLayouts({ maxEntries: MAX_STORED_AUDIT_LAYOUTS, now });
      expect(pruned).toBe(5); // 35 - 30 = 5 oldest removed
      expect(mockStorage.length).toBe(MAX_STORED_AUDIT_LAYOUTS);
      // Oldest sess-00 should be removed
      expect(mockStorage.getItem(`${AUDIT_LABEL_KEY_PREFIX}sess-00`)).toBeNull();
      // Newest sess-34 should remain
      expect(mockStorage.getItem(`${AUDIT_LABEL_KEY_PREFIX}sess-34`)).toBeTruthy();
    });

    it("preserves keys in retainKeys option", () => {
      const oldTime = 100;
      const keyToRetain = `${AUDIT_LABEL_KEY_PREFIX}important-sess`;
      mockStorage.setItem(
        keyToRetain,
        JSON.stringify({ version: 1, updatedAt: oldTime, positions: { ip: { x: 10, y: 10 } } }),
      );

      const pruned = pruneStaleAuditLayouts({ retainKeys: [keyToRetain], maxAgeMs: 1000, now: 100000 });
      expect(pruned).toBe(0);
      expect(mockStorage.getItem(keyToRetain)).toBeTruthy();
    });

    it("automatically prunes and retries when saveLayoutToStorage encounters quota exhaustion", () => {
      const oldKey = `${AUDIT_LABEL_KEY_PREFIX}old-session`;
      mockStorage.setItem(
        oldKey,
        JSON.stringify({ version: 1, updatedAt: 1000, positions: { a: { x: 1, y: 1 } } }),
      );

      let attempts = 0;
      const originalSetItem = mockStorage.setItem.bind(mockStorage);
      mockStorage.setItem = (key: string, value: string) => {
        attempts++;
        if (attempts === 1) {
          throw new DOMException("The quota has been exceeded", "QuotaExceededError");
        }
        originalSetItem(key, value);
      };

      const ok = saveLayoutToStorage("new-key", { test: { x: 50, y: 50 } });
      expect(ok).toBe(true);
      expect(attempts).toBe(2); // First failed with QuotaExceededError, second succeeded after prune
      expect(mockStorage.getItem(oldKey)).toBeNull(); // Old audit entry was pruned to free space
    });
  });
});
