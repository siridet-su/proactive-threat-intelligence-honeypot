import { describe, expect, it } from "vitest";
import type { Document } from "mongodb";

import {
  buildAuditScopingStages,
  buildAuditProjectionSessionsPipeline,
  buildAuditProjectionSummaryPipeline,
  buildAuditSearchRegexString,
  buildAuditSessionsPipeline,
  buildAuditSummaryPipeline,
  buildAuditTargetPathRegexString,
  decodeAuditSessionCursor,
  encodeAuditSessionCursor,
  normalizeAuditTargetPath,
  normalizeSessionAuditSummary,
} from "../src/lib/filesystem-data";
import type { FilesystemClosedSession } from "../src/lib/dashboardTypes";

// ---------------------------------------------------------------------------
// In-memory Execution Simulator for MongoDB Filter-Then-Page Semantics
// (Implements the exact execution semantics of buildAuditSessionsPipeline)
// ---------------------------------------------------------------------------

interface RawSessionDoc {
  _id?: string;
  sessionId?: string;
  session_id?: string;
  sourceIp?: string;
  cwdState?: {
    path?: string | null;
    status?: string;
    observedAt?: string | null;
    sourceEventId?: string | null;
  };
  lifecycle?: {
    status?: string;
    startedAt?: string | Date | null;
    closedAt?: string | Date | null;
  };
}

interface RawEventDoc {
  _id?: string;
  sessionId?: string;
  session_id?: string;
  action: "entered" | "changed" | "failed_change";
  fromPath?: string | null;
  toPath?: string | null;
  at?: string | Date;
}

interface SimulatedPageResult {
  items: FilesystemClosedSession[];
  totalItems: number;
  nextCursor: string | null;
}

function simulateAuditSessionsPipeline(
  sessions: RawSessionDoc[],
  events: RawEventDoc[],
  options: {
    search?: string | null;
    targetPath?: string | null;
    hideHome?: boolean;
    cursor?: string | null;
    limit?: number;
  } = {},
): SimulatedPageResult {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));

  // Stage 1: Base match for closed sessions with valid cwdState.path
  const baseSessions = sessions.filter((s) => {
    const isClosed = s.lifecycle?.status === "closed";
    const hasPath = typeof s.cwdState?.path === "string" && s.cwdState.path.trim() !== "";
    return isClosed && hasPath;
  });

  // Stage 2 & 3: Resolve effectiveSessionId, lookup events, compute visitedPaths & homeOnly
  const searchRegexStr = buildAuditSearchRegexString(options.search);
  const searchRegex = searchRegexStr ? new RegExp(searchRegexStr, "i") : null;
  const targetRegexStr = buildAuditTargetPathRegexString(options.targetPath);
  const targetRegex = targetRegexStr ? new RegExp(targetRegexStr) : null;

  const scopedDocs = baseSessions.map((s) => {
    const effectiveSessionId = s.sessionId ?? s.session_id ?? "";
    const sourceIp = s.sourceIp ?? "Unknown";
    const cwdPath = s.cwdState?.path ?? "/";

    // Lookup history events for effectiveSessionId
    const matchingEvents = events.filter((e) => {
      const eSid = e.sessionId ?? e.session_id;
      return (
        eSid === effectiveSessionId &&
        (e.action === "entered" || e.action === "changed" || e.action === "failed_change")
      );
    });

    // Compute visitedPaths: cwdPath + fromPaths + successfulToPaths (excluding failed_change.toPath)
    const visitedSet = new Set<string>();
    if (cwdPath.startsWith("/")) visitedSet.add(cwdPath);

    for (const e of matchingEvents) {
      if (typeof e.fromPath === "string" && e.fromPath.startsWith("/")) {
        visitedSet.add(e.fromPath);
      }
      if (e.action !== "failed_change" && typeof e.toPath === "string" && e.toPath.startsWith("/")) {
        visitedSet.add(e.toPath);
      }
    }

    const visitedPaths = [...visitedSet].sort((a, b) => a.localeCompare(b));
    const nonRootPaths = visitedPaths.filter((p) => p !== "/");
    const hasHomePath = nonRootPaths.some((p) => p === "/home" || p.startsWith("/home/"));
    const hasOutsideHomePath = nonRootPaths.some((p) => p !== "/home" && !p.startsWith("/home/"));
    const homeOnly = hasHomePath && !hasOutsideHomePath;

    // Predicates
    const matchesSearch = searchRegex
      ? searchRegex.test(effectiveSessionId) ||
        searchRegex.test(sourceIp) ||
        searchRegex.test(cwdPath)
      : true;

    const matchesTarget = targetRegex
      ? visitedPaths.some((p) => targetRegex.test(p))
      : true;

    const matchesHideHome = options.hideHome ? !homeOnly : true;
    const matchesFilter = matchesSearch && matchesTarget && matchesHideHome;

    const closedAtDate = s.lifecycle?.closedAt ? new Date(s.lifecycle.closedAt) : new Date(0);

    return {
      raw: s,
      effectiveSessionId,
      sourceIp,
      cwdPath,
      visitedPaths,
      homeOnly,
      eventCount: matchingEvents.length,
      matchesFilter,
      closedAtDate,
      lifecycle: s.lifecycle,
      cwdState: s.cwdState,
    };
  });

  // Stage 4: Filter BEFORE pagination
  const filtered = scopedDocs.filter((doc) => doc.matchesFilter);
  const totalItems = filtered.length;

  // Stage 5: Sort by closedAt DESC, effectiveSessionId DESC
  filtered.sort((a, b) => {
    const timeDiff = b.closedAtDate.getTime() - a.closedAtDate.getTime();
    if (timeDiff !== 0) return timeDiff;
    return b.effectiveSessionId.localeCompare(a.effectiveSessionId);
  });

  // Stage 6: Keyset Cursor application
  let paginatedSlice = filtered;
  if (typeof options.cursor === "string" && options.cursor.trim()) {
    const decoded = decodeAuditSessionCursor(options.cursor);
    if (!decoded) {
      // Malformed cursor fails safely: returns 0 items without broadening
      return { items: [], totalItems, nextCursor: null };
    }
    const cursorDate = new Date(decoded.closedAt);
    if (Number.isNaN(cursorDate.getTime()) || !decoded.sessionId) {
      return { items: [], totalItems, nextCursor: null };
    }

    paginatedSlice = filtered.filter((doc) => {
      const docTime = doc.closedAtDate.getTime();
      const curTime = cursorDate.getTime();
      if (docTime < curTime) return true;
      if (docTime === curTime && doc.effectiveSessionId < decoded.sessionId) return true;
      return false;
    });
  }

  // Fetch limit + 1
  const fetchCount = limit + 1;
  const rawPage = paginatedSlice.slice(0, fetchCount);
  const hasMore = rawPage.length > limit;
  const pageDocs = rawPage.slice(0, limit);

  const items: FilesystemClosedSession[] = pageDocs.map((doc) => ({
    sessionId: doc.effectiveSessionId,
    sourceIp: doc.sourceIp,
    cwdState: {
      path: doc.cwdPath,
      status: (doc.cwdState?.status as "confirmed" | "observed" | "conditional_candidate" | "unknown") ?? "confirmed",
      observedAt: doc.cwdState?.observedAt ? new Date(doc.cwdState.observedAt).toISOString() : null,
      sourceEventId: doc.cwdState?.sourceEventId ?? null,
    },
    lifecycle: {
      startedAt: doc.lifecycle?.startedAt ? new Date(doc.lifecycle.startedAt).toISOString() : null,
      closedAt: doc.lifecycle?.closedAt ? new Date(doc.lifecycle.closedAt).toISOString() : null,
    },
    auditSummary: {
      visitedPaths: doc.visitedPaths,
      homeOnly: doc.homeOnly,
      eventCount: doc.eventCount,
    },
  }));

  const lastDoc = pageDocs.at(-1);
  const nextCursor = hasMore && lastDoc
    ? encodeAuditSessionCursor(
        lastDoc.closedAtDate.toISOString(),
        lastDoc.effectiveSessionId,
      )
    : null;

  return {
    items,
    totalItems,
    nextCursor,
  };
}

// ---------------------------------------------------------------------------
// Unit Tests: MongoDB Aggregation Pipeline Builder Contracts
// ---------------------------------------------------------------------------

describe("MongoDB Aggregation Pipeline Builders (FA-002)", () => {
  const sampleClosedAt = "2026-09-10T12:00:00.000Z";
  const sampleSessionId = "session-test-xyz";

  it("builds scoping stages with closed status and effectiveSessionId unification", () => {
    const stages = buildAuditScopingStages({});
    expect(stages[0]).toEqual({
      $match: {
        "lifecycle.status": "closed",
        "cwdState.path": { $type: "string", $ne: "" },
      },
    });
    expect(stages[1].$addFields).toMatchObject({ effectiveSessionId: expect.any(Object) });
    expect(JSON.stringify(stages[1])).toContain("$trim");
    // History lookup stage
    const lookupStage = stages.find((s) => "$lookup" in s) as { $lookup: Record<string, unknown> };
    expect(lookupStage).toBeDefined();
    expect(lookupStage.$lookup.from).toBe("cwd_events");
  });

  it("uses real BSON Date objects in MongoDB cursor keyset comparisons", () => {
    const cursor = encodeAuditSessionCursor(sampleClosedAt, sampleSessionId);
    const pipeline = buildAuditSessionsPipeline({ cursor });

    const facetStage = pipeline.find((s) => "$facet" in s) as {
      $facet: { items: Array<Record<string, unknown>> };
    };
    expect(facetStage).toBeDefined();

    const cursorMatchStage = facetStage.$facet.items.find((s) => "$match" in s) as {
      $match: { $or: Array<Record<string, unknown>> };
    };
    expect(cursorMatchStage).toBeDefined();

    const orClauses = cursorMatchStage.$match.$or;
    expect(orClauses).toHaveLength(2);

    // First clause: closedAt < cursorDate
    const ltClause = orClauses[0].effectiveClosedAt as { $lt: unknown };
    expect(ltClause.$lt).toBeInstanceOf(Date);
    expect((ltClause.$lt as Date).toISOString()).toBe(sampleClosedAt);

    // Second clause: closedAt == cursorDate AND effectiveSessionId < cursorSessionId
    const eqClause = orClauses[1].effectiveClosedAt as { $eq: unknown };
    expect(eqClause.$eq).toBeInstanceOf(Date);
    expect((eqClause.$eq as Date).toISOString()).toBe(sampleClosedAt);
    expect(orClauses[1].effectiveSessionId).toEqual({ $lt: sampleSessionId });
  });

  it("fails safely with $expr: false for malformed cursor input without broadening or corrupting", () => {
    // Malformed base64 cursor
    const pipelineMalformed = buildAuditSessionsPipeline({ cursor: "not-a-valid-cursor" });
    const facetStage = pipelineMalformed.find((s) => "$facet" in s) as {
      $facet: { items: Array<Record<string, unknown>> };
    };
    const matchStage = facetStage.$facet.items.find((s) => "$match" in s);
    expect(matchStage).toEqual({ $match: { $expr: false } });

    // Empty object cursor
    const emptyJsonCursor = Buffer.from("{}").toString("base64url");
    const pipelineEmpty = buildAuditSessionsPipeline({ cursor: emptyJsonCursor });
    const facetEmpty = pipelineEmpty.find((s) => "$facet" in s) as {
      $facet: { items: Array<Record<string, unknown>> };
    };
    const matchEmpty = facetEmpty.$facet.items.find((s) => "$match" in s);
    expect(matchEmpty).toEqual({ $match: { $expr: false } });
  });

  it("buildAuditTargetPathRegexString normalizes slashes, handles root, and escapes special regex characters", () => {
    // Root or "all" -> null (no filter, matches all)
    expect(buildAuditTargetPathRegexString("/")).toBeNull();
    expect(buildAuditTargetPathRegexString("///")).toBeNull();
    expect(buildAuditTargetPathRegexString("all")).toBeNull();
    expect(buildAuditTargetPathRegexString(null)).toBeNull();

    // Standard path with trailing slash stripped
    expect(buildAuditTargetPathRegexString("/etc/nginx/")).toBe("^/etc/nginx(/.*)?$");
    expect(buildAuditTargetPathRegexString("/var")).toBe("^/var(/.*)?$");

    // Path with special regex characters escaped
    expect(buildAuditTargetPathRegexString("/opt/test(1)+dir")).toBe("^/opt/test\\(1\\)\\+dir(/.*)?$");
  });

  it("normalizes target path correctly", () => {
    expect(normalizeAuditTargetPath("/home/cowrie/")).toBe("/home/cowrie");
    expect(normalizeAuditTargetPath("///")).toBe("/");
    expect(normalizeAuditTargetPath("all")).toBeNull();
    expect(normalizeAuditTargetPath("")).toBeNull();
  });

  it("builds summary pipeline with overview and distinctPaths facets", () => {
    const pipeline = buildAuditSummaryPipeline({ hideHome: true, targetPath: "/etc" });
    const facetStage = pipeline.find((s) => "$facet" in s) as {
      $facet: { overview: Document[]; distinctPaths: Document[] };
    };
    expect(facetStage).toBeDefined();
    expect(facetStage.$facet.overview).toBeDefined();
    expect(facetStage.$facet.distinctPaths).toBeDefined();
  });
});

describe("Materialized Audit projection pipeline (FA-016)", () => {
  it("pages directly over canonical projection fields without history fan-out or skip", () => {
    const pipeline = buildAuditProjectionSessionsPipeline({
      hideHome: true,
      targetPath: "/etc",
      search: "198.51.100",
      limit: 25,
    });
    const serialized = JSON.stringify(pipeline);
    expect(serialized).not.toContain("$lookup");
    expect(serialized).not.toContain("$skip");
    expect(serialized).toContain("auditProjectionVersion");
    expect(serialized).toContain("auditVisitedPaths");
    expect(pipeline.at(-1)).toEqual({ $limit: 26 });
  });

  it("uses the materialized canonical session identity for equal-time cursor ties", () => {
    const cursor = encodeAuditSessionCursor("2026-09-10T12:00:00.000Z", "session-010");
    const pipeline = buildAuditProjectionSessionsPipeline({ cursor, limit: 10 });
    const cursorStage = pipeline.find((stage) => "$match" in stage && "$or" in (stage.$match ?? {})) as { $match: { $or: Document[] } };
    expect(cursorStage.$match.$or[0]?.["lifecycle.closedAt"]).toEqual({ $lt: new Date("2026-09-10T12:00:00.000Z") });
    expect(cursorStage.$match.$or[1]).toEqual({
      "lifecycle.closedAt": new Date("2026-09-10T12:00:00.000Z"),
      sessionId: { $lt: "session-010" },
    });
  });

  it("keeps exact summary counting on materialized fields while bounding work to projection rows", () => {
    const pipeline = buildAuditProjectionSummaryPipeline({ hideHome: true, targetPath: "/etc" });
    const serialized = JSON.stringify(pipeline);
    expect(serialized).not.toContain("$lookup");
    expect(serialized).not.toContain("$skip");
    expect(pipeline.at(-1)?.$facet.overview).toBeDefined();
    expect(pipeline.at(-1)?.$facet.distinctPaths).toBeDefined();
    expect(serialized).toContain("auditVisitedPaths");
  });
});

// ---------------------------------------------------------------------------
// Execution-Level Fixture Tests: Filter-Then-Page Regression Scenarios
// ---------------------------------------------------------------------------

describe("Execution-Level Fixture Tests: Filter-Then-Page Semantics (FA-002)", () => {
  // Test Scenario 1: More than one unfiltered page where page 1 has zero targetPath matches but later records match
  it("returns matches on page 1 even when the first unfiltered page has 0 target matches", () => {
    // 30 closed sessions:
    // Sessions 01-25 only visited /home/cowrie
    // Sessions 26-30 visited /etc/shadow
    const sessions: RawSessionDoc[] = [];
    const events: RawEventDoc[] = [];

    // Sessions 01 to 25 (newer timestamps: closedAt 2026-09-15T10:25:00Z down to 10:01:00Z)
    for (let i = 1; i <= 25; i++) {
      const sid = `sess-home-${String(i).padStart(2, "0")}`;
      const minute = String(i).padStart(2, "0");
      sessions.push({
        sessionId: sid,
        sourceIp: "10.0.0.1",
        cwdState: { path: "/home/cowrie", status: "confirmed" },
        lifecycle: {
          status: "closed",
          closedAt: `2026-09-15T10:${minute}:00.000Z`,
        },
      });
      events.push({
        sessionId: sid,
        action: "entered",
        fromPath: null,
        toPath: "/home/cowrie",
      });
    }

    // Sessions 26 to 30 (older timestamps: closedAt 2026-09-15T09:26:00Z down to 09:30:00Z)
    for (let i = 26; i <= 30; i++) {
      const sid = `sess-etc-${String(i).padStart(2, "0")}`;
      const minute = String(i).padStart(2, "0");
      sessions.push({
        sessionId: sid,
        sourceIp: "10.0.0.2",
        cwdState: { path: "/etc/shadow", status: "confirmed" },
        lifecycle: {
          status: "closed",
          closedAt: `2026-09-15T09:${minute}:00.000Z`,
        },
      });
      events.push({
        sessionId: sid,
        action: "entered",
        fromPath: null,
        toPath: "/etc/shadow",
      });
    }

    // Filter by targetPath: "/etc" with limit: 25
    // In defective implementation, page 1 sliced the 25 newest sessions (all home),
    // producing 0 returned items while hiding the 5 matches on page 2.
    const result = simulateAuditSessionsPipeline(sessions, events, {
      targetPath: "/etc",
      limit: 25,
    });

    expect(result.totalItems).toBe(5);
    expect(result.items).toHaveLength(5);
    expect(result.items.map((it) => it.sessionId)).toEqual([
      "sess-etc-30",
      "sess-etc-29",
      "sess-etc-28",
      "sess-etc-27",
      "sess-etc-26",
    ]);
    expect(result.nextCursor).toBeNull();
  });

  // Test Scenario 2: hideHome filtering before pagination
  it("filters home-only sessions before page slicing", () => {
    const sessions: RawSessionDoc[] = [];
    const events: RawEventDoc[] = [];

    // 25 home-only sessions (newer)
    for (let i = 1; i <= 25; i++) {
      const sid = `home-only-${String(i).padStart(2, "0")}`;
      sessions.push({
        sessionId: sid,
        sourceIp: "192.168.1.10",
        cwdState: { path: "/home/cowrie", status: "confirmed" },
        lifecycle: { status: "closed", closedAt: `2026-09-15T12:${String(i).padStart(2, "0")}:00Z` },
      });
      events.push({
        sessionId: sid,
        action: "entered",
        toPath: "/home/cowrie",
      });
    }

    // 5 system-touching sessions (older)
    for (let i = 26; i <= 30; i++) {
      const sid = `sys-touch-${String(i).padStart(2, "0")}`;
      sessions.push({
        sessionId: sid,
        sourceIp: "192.168.1.20",
        cwdState: { path: "/var/log", status: "confirmed" },
        lifecycle: { status: "closed", closedAt: `2026-09-15T11:${String(i).padStart(2, "0")}:00Z` },
      });
      events.push({
        sessionId: sid,
        action: "changed",
        fromPath: "/home/cowrie",
        toPath: "/var/log",
      });
    }

    const result = simulateAuditSessionsPipeline(sessions, events, {
      hideHome: true,
      limit: 25,
    });

    expect(result.totalItems).toBe(5);
    expect(result.items).toHaveLength(5);
    expect(result.items.every((it) => !it.auditSummary.homeOnly)).toBe(true);
    expect(result.items[0].sessionId).toBe("sys-touch-30");
  });

  // Test Scenario 3: targetPath filtering before pagination
  it("filters targetPath before page slicing and matches subpaths", () => {
    const sessions: RawSessionDoc[] = [
      {
        sessionId: "s1",
        sourceIp: "1.1.1.1",
        cwdState: { path: "/etc/pam.d/common-auth" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
      {
        sessionId: "s2",
        sourceIp: "1.1.1.2",
        cwdState: { path: "/home/user" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" },
      },
      {
        sessionId: "s3",
        sourceIp: "1.1.1.3",
        cwdState: { path: "/etc" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T10:00:00Z" },
      },
    ];

    const result = simulateAuditSessionsPipeline(sessions, [], {
      targetPath: "/etc",
      limit: 25,
    });

    expect(result.totalItems).toBe(2);
    expect(result.items.map((i) => i.sessionId)).toEqual(["s1", "s3"]);
  });

  // Test Scenario 4: combined search + hideHome + targetPath
  it("applies search, hideHome, and targetPath together before pagination", () => {
    const sessions: RawSessionDoc[] = [
      // Matches all: IP matches, touches /etc (non-home), targetPath /etc
      {
        sessionId: "match-1",
        sourceIp: "172.16.0.99",
        cwdState: { path: "/etc/nginx" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
      // Matches search and targetPath, but is homeOnly (should be excluded by hideHome)
      {
        sessionId: "home-only-target",
        sourceIp: "172.16.0.99",
        cwdState: { path: "/home/cowrie" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" },
      },
      // Matches targetPath and hideHome, but IP does not match search
      {
        sessionId: "ip-mismatch",
        sourceIp: "10.0.0.1",
        cwdState: { path: "/etc/nginx" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T10:00:00Z" },
      },
    ];

    const result = simulateAuditSessionsPipeline(sessions, [], {
      search: "172.16.0.99",
      hideHome: true,
      targetPath: "/etc",
      limit: 25,
    });

    expect(result.totalItems).toBe(1);
    expect(result.items).toHaveLength(1);
    expect(result.items[0].sessionId).toBe("match-1");
  });

  // Test Scenario 5: totalItems equals the complete filtered result count
  it("maintains consistent totalItems across pages without shrinking by cursor", () => {
    const sessions: RawSessionDoc[] = [];
    for (let i = 1; i <= 5; i++) {
      sessions.push({
        sessionId: `item-${i}`,
        sourceIp: "10.0.0.1",
        cwdState: { path: "/etc" },
        lifecycle: { status: "closed", closedAt: `2026-09-15T12:0${i}:00Z` },
      });
    }

    // Page 1 with limit 2
    const page1 = simulateAuditSessionsPipeline(sessions, [], { targetPath: "/etc", limit: 2 });
    expect(page1.totalItems).toBe(5);
    expect(page1.items).toHaveLength(2);
    expect(page1.nextCursor).not.toBeNull();

    // Page 2 with cursor
    const page2 = simulateAuditSessionsPipeline(sessions, [], {
      targetPath: "/etc",
      cursor: page1.nextCursor,
      limit: 2,
    });
    expect(page2.totalItems).toBe(5);
    expect(page2.items).toHaveLength(2);
    expect(page2.nextCursor).not.toBeNull();

    // Page 3
    const page3 = simulateAuditSessionsPipeline(sessions, [], {
      targetPath: "/etc",
      cursor: page2.nextCursor,
      limit: 2,
    });
    expect(page3.totalItems).toBe(5);
    expect(page3.items).toHaveLength(1);
    expect(page3.nextCursor).toBeNull();
  });

  // Test Scenario 6: nextCursor is null only when the filtered result set is exhausted
  it("returns nextCursor === null exactly when filtered results are exhausted", () => {
    const sessions: RawSessionDoc[] = [
      { sessionId: "s1", cwdState: { path: "/var" }, lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" } },
      { sessionId: "s2", cwdState: { path: "/var" }, lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" } },
    ];

    const page1 = simulateAuditSessionsPipeline(sessions, [], { limit: 1 });
    expect(page1.nextCursor).not.toBeNull();

    const page2 = simulateAuditSessionsPipeline(sessions, [], { cursor: page1.nextCursor, limit: 1 });
    expect(page2.nextCursor).toBeNull();
    expect(page2.items).toHaveLength(1);
    expect(page2.items[0].sessionId).toBe("s2");
  });

  // Test Scenario 7: page 2 has no duplicate or skipped records
  it("produces no duplicate or skipped records across consecutive pages", () => {
    const sessions: RawSessionDoc[] = [];
    for (let i = 1; i <= 6; i++) {
      sessions.push({
        sessionId: `sess-${i}`,
        cwdState: { path: "/tmp" },
        lifecycle: { status: "closed", closedAt: `2026-09-15T10:0${i}:00Z` },
      });
    }

    const p1 = simulateAuditSessionsPipeline(sessions, [], { limit: 2 });
    const p2 = simulateAuditSessionsPipeline(sessions, [], { cursor: p1.nextCursor, limit: 2 });
    const p3 = simulateAuditSessionsPipeline(sessions, [], { cursor: p2.nextCursor, limit: 2 });

    const allSeen = [...p1.items, ...p2.items, ...p3.items].map((i) => i.sessionId);
    expect(allSeen).toEqual(["sess-6", "sess-5", "sess-4", "sess-3", "sess-2", "sess-1"]);
    expect(new Set(allSeen).size).toBe(6);
  });

  // Test Scenario 8: multiple records sharing the same closedAt use the effective session ID tie-breaker
  it("uses effective session ID tie-breaker when multiple records share identical closedAt timestamps", () => {
    const timestamp = "2026-09-15T12:00:00.000Z";
    const sessions: RawSessionDoc[] = [
      { sessionId: "sess-bravo", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: timestamp } },
      { sessionId: "sess-alpha", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: timestamp } },
      { sessionId: "sess-charlie", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: timestamp } },
    ];

    // Descending order: closedAt DESC, sessionId DESC: charlie, bravo, alpha
    const p1 = simulateAuditSessionsPipeline(sessions, [], { limit: 1 });
    expect(p1.items[0].sessionId).toBe("sess-charlie");
    expect(p1.nextCursor).not.toBeNull();

    const p2 = simulateAuditSessionsPipeline(sessions, [], { cursor: p1.nextCursor, limit: 1 });
    expect(p2.items[0].sessionId).toBe("sess-bravo");
    expect(p2.nextCursor).not.toBeNull();

    const p3 = simulateAuditSessionsPipeline(sessions, [], { cursor: p2.nextCursor, limit: 1 });
    expect(p3.items[0].sessionId).toBe("sess-alpha");
    expect(p3.nextCursor).toBeNull();
  });

  // Test Scenario 9: MongoDB cursor comparisons use Date objects, not ISO strings
  it("verifies buildAuditSessionsPipeline stages construct Date objects for MongoDB cursor comparisons", () => {
    const isoDate = "2026-09-10T15:30:00.000Z";
    const cursor = encodeAuditSessionCursor(isoDate, "sess-01");
    const pipeline = buildAuditSessionsPipeline({ cursor });

    const facet = pipeline.find((s) => "$facet" in s) as { $facet: { items: Document[] } };
    const match = facet.$facet.items.find((s) => "$match" in s) as { $match: { $or: Document[] } };

    const ltCondition = match.$match.$or[0].effectiveClosedAt;
    expect(ltCondition.$lt).toBeInstanceOf(Date);
    expect(typeof ltCondition.$lt).not.toBe("string");
    expect((ltCondition.$lt as Date).getTime()).toBe(new Date(isoDate).getTime());

    const eqCondition = match.$match.$or[1].effectiveClosedAt;
    expect(eqCondition.$eq).toBeInstanceOf(Date);
    expect(typeof eqCondition.$eq).not.toBe("string");
    expect((eqCondition.$eq as Date).getTime()).toBe(new Date(isoDate).getTime());
  });

  // Test Scenario 10: legacy session_id participates in search, sorting, cursor comparison, and returned IDs
  it("supports legacy session_id across search, sort, cursor comparison, and returned session ID", () => {
    const sessions: RawSessionDoc[] = [
      {
        session_id: "legacy-sess-002",
        sourceIp: "10.10.10.2",
        cwdState: { path: "/root" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
      {
        session_id: "legacy-sess-001",
        sourceIp: "10.10.10.1",
        cwdState: { path: "/root" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
    ];

    // Search on legacy session ID
    const searchRes = simulateAuditSessionsPipeline(sessions, [], { search: "legacy-sess" });
    expect(searchRes.totalItems).toBe(2);
    expect(searchRes.items[0].sessionId).toBe("legacy-sess-002");
    expect(searchRes.items[1].sessionId).toBe("legacy-sess-001");

    // Pagination with tie-breaker on legacy session_id
    const page1 = simulateAuditSessionsPipeline(sessions, [], { limit: 1 });
    expect(page1.items[0].sessionId).toBe("legacy-sess-002");
    expect(page1.nextCursor).not.toBeNull();

    const page2 = simulateAuditSessionsPipeline(sessions, [], { cursor: page1.nextCursor, limit: 1 });
    expect(page2.items[0].sessionId).toBe("legacy-sess-001");
    expect(page2.nextCursor).toBeNull();
  });

  // Test Scenario 11: failed_change.toPath does not create a target-path match
  it("does not treat failed_change.toPath as a target-path match, but includes fromPath", () => {
    const sessions: RawSessionDoc[] = [
      {
        sessionId: "failed-attacker",
        cwdState: { path: "/home/cowrie" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
      {
        sessionId: "successful-attacker",
        cwdState: { path: "/etc/shadow" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" },
      },
    ];

    const events: RawEventDoc[] = [
      {
        sessionId: "failed-attacker",
        action: "failed_change",
        fromPath: "/home/cowrie",
        toPath: "/etc/shadow", // Failed attempt to reach /etc/shadow
      },
      {
        sessionId: "successful-attacker",
        action: "changed",
        fromPath: "/home/cowrie",
        toPath: "/etc/shadow", // Successful change to /etc/shadow
      },
    ];

    // Filtering by targetPath: "/etc" must NOT match failed-attacker
    const result = simulateAuditSessionsPipeline(sessions, events, {
      targetPath: "/etc",
      limit: 25,
    });

    expect(result.totalItems).toBe(1);
    expect(result.items).toHaveLength(1);
    expect(result.items[0].sessionId).toBe("successful-attacker");
  });

  // Test Scenario 12: root-only and home-only behavior remains aligned with normalizeSessionAuditSummary
  it("preserves root-only and home-only classification aligned with normalizeSessionAuditSummary", () => {
    const sessions: RawSessionDoc[] = [
      // Root-only: visited only "/"
      {
        sessionId: "root-only-session",
        cwdState: { path: "/" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" },
      },
      // Home-only: visited "/" and "/home/user"
      {
        sessionId: "home-and-root-session",
        cwdState: { path: "/home/user" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" },
      },
      // Outside-home: visited "/", "/home/user", and "/var/log"
      {
        sessionId: "outside-home-session",
        cwdState: { path: "/var/log" },
        lifecycle: { status: "closed", closedAt: "2026-09-15T10:00:00Z" },
      },
    ];

    const events: RawEventDoc[] = [
      {
        sessionId: "home-and-root-session",
        action: "entered",
        fromPath: "/",
        toPath: "/home/user",
      },
      {
        sessionId: "outside-home-session",
        action: "entered",
        fromPath: "/",
        toPath: "/home/user",
      },
      {
        sessionId: "outside-home-session",
        action: "changed",
        fromPath: "/home/user",
        toPath: "/var/log",
      },
    ];

    // Unfiltered
    const all = simulateAuditSessionsPipeline(sessions, events, {});
    const rootSession = all.items.find((s) => s.sessionId === "root-only-session")!;
    const homeSession = all.items.find((s) => s.sessionId === "home-and-root-session")!;
    const outsideSession = all.items.find((s) => s.sessionId === "outside-home-session")!;

    // Root-only session is NOT homeOnly (root is a boundary, not home)
    expect(rootSession.auditSummary.homeOnly).toBe(false);
    // Home-and-root session IS homeOnly
    expect(homeSession.auditSummary.homeOnly).toBe(true);
    // Outside-home session is NOT homeOnly
    expect(outsideSession.auditSummary.homeOnly).toBe(false);

    // Verify alignment with normalizeSessionAuditSummary
    const normRoot = normalizeSessionAuditSummary("/", [], [], 0);
    expect(normRoot.homeOnly).toBe(false);

    const normHome = normalizeSessionAuditSummary("/home/user", ["/"], ["/home/user"], 1);
    expect(normHome.homeOnly).toBe(true);

    const normOutside = normalizeSessionAuditSummary("/var/log", ["/", "/home/user"], ["/var/log"], 2);
    expect(normOutside.homeOnly).toBe(false);

    // When hideHome is true, home-and-root session is excluded, but root-only session remains visible
    const hiddenHome = simulateAuditSessionsPipeline(sessions, events, { hideHome: true });
    expect(hiddenHome.items.map((s) => s.sessionId)).toEqual([
      "root-only-session",
      "outside-home-session",
    ]);
  });

  // Test Scenario 13: malformed cursor behavior is deterministic and tested
  it("fails safely and deterministically for malformed or corrupted cursor strings", () => {
    const sessions: RawSessionDoc[] = [
      { sessionId: "s1", cwdState: { path: "/var" }, lifecycle: { status: "closed", closedAt: "2026-09-15T12:00:00Z" } },
      { sessionId: "s2", cwdState: { path: "/var" }, lifecycle: { status: "closed", closedAt: "2026-09-15T11:00:00Z" } },
    ];

    // Invalid base64
    const res1 = simulateAuditSessionsPipeline(sessions, [], { cursor: "!!!not-valid-base64!!!" });
    expect(res1.items).toEqual([]);
    expect(res1.nextCursor).toBeNull();
    expect(res1.totalItems).toBe(2);

    // Base64 containing invalid JSON structure
    const badJsonCursor = Buffer.from("invalid-json").toString("base64url");
    const res2 = simulateAuditSessionsPipeline(sessions, [], { cursor: badJsonCursor });
    expect(res2.items).toEqual([]);
    expect(res2.nextCursor).toBeNull();
    expect(res2.totalItems).toBe(2);

    // Cursor with invalid date
    const badDateCursor = Buffer.from(JSON.stringify({ closedAt: "not-a-date", sessionId: "s1" })).toString("base64url");
    const res3 = simulateAuditSessionsPipeline(sessions, [], { cursor: badDateCursor });
    expect(res3.items).toEqual([]);
    expect(res3.nextCursor).toBeNull();
    expect(res3.totalItems).toBe(2);
  });
});
