import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import type { Document } from "mongodb";
import {
  CLOSED_AUDIT_PATHS_CACHE_MAX_ENTRIES,
  closedAuditPathsCache,
  getFilesystemTopology,
} from "@/lib/filesystem-server";
import { createBoundedLruCache } from "@/lib/bounded-lru-cache";
import * as mongo from "@/lib/mongodb";

type SessionDocument = Document & {
  sessionId: string;
  lifecycle: { status: "active" | "closed"; closedAt?: string };
  cwdState: { path: string; observedAt: string; status: "confirmed" };
};

function sessionDocument(sessionId: string, status: "active" | "closed"): SessionDocument {
  return {
    sessionId,
    sourceIp: "192.0.2.10",
    lifecycle: {
      status,
      ...(status === "closed" ? { closedAt: "2026-09-19T00:00:00.000Z" } : {}),
    },
    cwdState: {
      path: "/var/tmp",
      observedAt: "2026-09-19T00:00:00.000Z",
      status: "confirmed",
    },
  };
}

function auditPaths(sessionId: string, path = "/var/tmp"): Document {
  return {
    _id: sessionId,
    fromPaths: ["/"],
    toPaths: [path],
    eventCount: 1,
  };
}

describe("bounded LRU cache", () => {
  it("enforces capacity and evicts the oldest entry deterministically", () => {
    const cache = createBoundedLruCache<string, number>({ maxEntries: 3 });

    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.set("d", 4);

    expect(cache.size()).toBe(3);
    expect(cache.has("a")).toBe(false);
    expect(cache.get("b")).toBe(2);
  });

  it("refreshes recency on read and on duplicate writes without growing", () => {
    const cache = createBoundedLruCache<string, string>({ maxEntries: 2 });

    cache.set("a", "old-a");
    cache.set("b", "b");
    expect(cache.get("a")).toBe("old-a");
    cache.set("c", "c");
    expect(cache.has("b")).toBe(false);
    expect(cache.size()).toBe(2);

    cache.set("a", "new-a");
    expect(cache.size()).toBe(2);
    cache.set("d", "d");
    expect(cache.has("c")).toBe(false);
    expect(cache.get("a")).toBe("new-a");
  });

  it("supports capacity zero and rejects invalid capacities", () => {
    const disabled = createBoundedLruCache<string, number>({ maxEntries: 0 });
    disabled.set("a", 1);
    expect(disabled.size()).toBe(0);
    expect(disabled.get("a")).toBeUndefined();

    for (const maxEntries of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => createBoundedLruCache({ maxEntries })).toThrow(RangeError);
    }
  });
});

describe("FA-011 production closed-session cache integration", () => {
  let activeDocuments: SessionDocument[] = [];
  let closedDocuments: SessionDocument[] = [];
  let rows = new Map<string, Document>();
  let aggregateCalls: string[][] = [];
  let stateFindCalls = 0;

  function installMongoMock() {
    const stateCollection = {
      find: vi.fn((filter: Document) => {
        stateFindCalls += 1;
        const documents = filter["lifecycle.status"] === "active" ? activeDocuments : closedDocuments;
        const query = {
          sort: vi.fn(),
          limit: vi.fn(),
          allowDiskUse: vi.fn(),
          toArray: vi.fn().mockResolvedValue(documents),
        };
        query.sort.mockReturnValue(query);
        query.limit.mockReturnValue(query);
        query.allowDiskUse.mockReturnValue(query);
        return query;
      }),
    };
    const historyCollection = {
      aggregate: vi.fn((pipeline: Document[]) => {
        const match = pipeline.find((stage) => "$match" in stage)?.$match as Document | undefined;
        const sessionIds = [...new Set(((match?.$or as Document[] | undefined) ?? []).flatMap((branch) => {
          const condition = Object.values(branch)[0] as Document | undefined;
          return (condition?.$in as string[] | undefined) ?? [];
        }))];
        aggregateCalls.push(sessionIds);
        return {
          toArray: vi.fn().mockResolvedValue(sessionIds.flatMap((sessionId) => {
            const row = rows.get(sessionId);
            return row ? [row] : [];
          })),
        };
      }),
    };
    const client = {
      db: () => ({
        collection: (name: string) => name === "cwd_session_state" ? stateCollection : historyCollection,
      }),
    };
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue(client as unknown as Awaited<ReturnType<typeof mongo.getMongoClient>>);
  }

  async function readSnapshot({ closed = [], active = [] }: { closed?: string[]; active?: string[] } = {}) {
    closedDocuments = closed.map((sessionId) => sessionDocument(sessionId, "closed"));
    activeDocuments = active.map((sessionId) => sessionDocument(sessionId, "active"));
    return getFilesystemTopology();
  }

  beforeEach(() => {
    closedAuditPathsCache.clear();
    activeDocuments = [];
    closedDocuments = [];
    rows = new Map();
    aggregateCalls = [];
    stateFindCalls = 0;
    installMongoMock();
  });

  it("keeps rolling closed-session windows bounded and refetches an evicted session", async () => {
    for (let index = 0; index < CLOSED_AUDIT_PATHS_CACHE_MAX_ENTRIES + 5; index += 1) {
      const sessionId = `closed-${index}`;
      rows.set(sessionId, auditPaths(sessionId));
      await readSnapshot({ closed: [sessionId] });
      expect(closedAuditPathsCache.size()).toBeLessThanOrEqual(CLOSED_AUDIT_PATHS_CACHE_MAX_ENTRIES);
    }

    const firstFetches = aggregateCalls.filter((sessionIds) => sessionIds.includes("closed-0")).length;
    rows.set("closed-0", auditPaths("closed-0", "/re-fetched"));
    const snapshot = await readSnapshot({ closed: ["closed-0"] });

    expect(aggregateCalls.filter((sessionIds) => sessionIds.includes("closed-0"))).toHaveLength(firstFetches + 1);
    expect(snapshot.recentClosedSessions[0]?.auditSummary.visitedPaths).toEqual(["/", "/re-fetched", "/var/tmp"].sort());
    expect(closedAuditPathsCache.size()).toBeLessThanOrEqual(CLOSED_AUDIT_PATHS_CACHE_MAX_ENTRIES);
  });

  it("preserves an immutable cache hit and ordinary refreshes do not reset the cache", async () => {
    rows.set("closed-stable", auditPaths("closed-stable", "/first"));
    const first = await readSnapshot({ closed: ["closed-stable"] });
    rows.set("closed-stable", auditPaths("closed-stable", "/changed-in-database"));
    const second = await readSnapshot({ closed: ["closed-stable"] });

    expect(aggregateCalls).toHaveLength(1);
    expect(second.recentClosedSessions[0]?.auditSummary).toEqual(first.recentClosedSessions[0]?.auditSummary);
    expect(second.recentClosedSessions[0]?.auditSummary.visitedPaths).toContain("/first");
    expect(second.recentClosedSessions[0]?.auditSummary.visitedPaths).not.toContain("/changed-in-database");
  });

  it("negative-caches a closed session with no aggregation result", async () => {
    const first = await readSnapshot({ closed: ["closed-empty"] });
    const second = await readSnapshot({ closed: ["closed-empty"] });

    expect(aggregateCalls).toEqual([["closed-empty"]]);
    expect(closedAuditPathsCache.has("closed-empty")).toBe(true);
    expect(first.recentClosedSessions[0]?.auditSummary.eventCount).toBe(0);
    expect(second.recentClosedSessions[0]?.auditSummary.eventCount).toBe(0);
  });

  it("never caches active sessions and continues live aggregation on refresh", async () => {
    rows.set("active-live", auditPaths("active-live", "/live-first"));
    const first = await readSnapshot({ active: ["active-live"] });
    rows.set("active-live", auditPaths("active-live", "/live-second"));
    const second = await readSnapshot({ active: ["active-live"] });

    expect(closedAuditPathsCache.has("active-live")).toBe(false);
    expect(aggregateCalls).toEqual([["active-live"], ["active-live"]]);
    expect(first.sessions[0]?.auditSummary.visitedPaths).toContain("/live-first");
    expect(second.sessions[0]?.auditSummary.visitedPaths).toContain("/live-second");
  });

  it("does not reuse a closed-cache value if the same ID is active", async () => {
    rows.set("reused-id", auditPaths("reused-id", "/closed-value"));
    await readSnapshot({ closed: ["reused-id"] });
    rows = new Map();

    const activeSnapshot = await readSnapshot({ active: ["reused-id"] });

    expect(closedAuditPathsCache.has("reused-id")).toBe(true);
    expect(aggregateCalls).toEqual([["reused-id"], ["reused-id"]]);
    expect(activeSnapshot.sessions[0]?.auditSummary.visitedPaths).toEqual(["/var/tmp"]);
    expect(activeSnapshot.sessions[0]?.auditSummary.eventCount).toBe(0);
  });

  it("coalesces simultaneous snapshots into one database refresh", async () => {
    rows.set("closed-concurrent", auditPaths("closed-concurrent"));
    closedDocuments = [sessionDocument("closed-concurrent", "closed")];
    const [first, second] = await Promise.all([getFilesystemTopology(), getFilesystemTopology()]);

    expect(first).toEqual(second);
    expect(aggregateCalls).toEqual([["closed-concurrent"]]);
    expect(stateFindCalls).toBe(2);
  });
});
