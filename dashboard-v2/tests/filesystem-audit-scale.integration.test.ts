import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { MongoClient, type Collection, type Document } from "mongodb";
import {
  buildAuditProjectionSessionsPipeline,
  buildAuditProjectionSummaryPipeline,
  encodeAuditSessionCursor,
} from "@/lib/filesystem-data";
import { getAuditDirectorySummary, getAuditSessions } from "@/lib/filesystem-server";
import * as mongo from "@/lib/mongodb";
import { AUDIT_PROJECTION_VERSION } from "@/lib/filesystem-data";
import { validateFilesystemAuditTestTarget } from "../scripts/filesystem-audit-test-target.mjs";

const integrationUri = process.env.FA016_MONGO_URI;
const integrationDatabase = process.env.FA016_MONGO_DB;
const integrationRunId = process.env.FA016_MONGO_RUN_ID;
const configured = [integrationUri, integrationDatabase, integrationRunId].some((value) => value !== undefined);
const target = configured
  ? validateFilesystemAuditTestTarget({ uri: integrationUri, databaseName: integrationDatabase, runId: integrationRunId })
  : null;
const run = integrationUri ? describe : describe.skip;

function metricValues(value: unknown, key: string, result: number[] = []): number[] {
  if (!value || typeof value !== "object") return result;
  if (Array.isArray(value)) {
    value.forEach((item) => metricValues(item, key, result));
    return result;
  }
  const record = value as Record<string, unknown>;
  if (typeof record[key] === "number") result.push(record[key] as number);
  Object.values(record).forEach((item) => metricValues(item, key, result));
  return result;
}

function maxMetric(explain: unknown, key: string): number {
  return Math.max(0, ...metricValues(explain, key));
}

run("FA-016 isolated MongoDB retained Audit scale", () => {
  let client: MongoClient;
  let database: ReturnType<MongoClient["db"]>;
  let projection: Collection<Document>;
  const aggregateCommands: Document[] = [];
  const sessionCount = 1900;

  beforeAll(async () => {
    client = new MongoClient(target!.uri, { monitorCommands: true });
    client.on("commandStarted", (event) => {
      if (event.commandName === "aggregate") aggregateCommands.push(event.command);
    });
    await client.connect();
    database = client.db(target!.databaseName);
    await database.dropDatabase();
    projection = database.collection("cwd_audit_projection");
    await projection.createIndex({ lifecycleStatus: 1 });
    await projection.createIndex({ "lifecycle.status": 1, "lifecycle.closedAt": -1, sessionId: -1 });
    await projection.createIndex({ "lifecycle.status": 1, auditHomeOnly: 1, "lifecycle.closedAt": -1, sessionId: -1 });
    await projection.createIndex({ "lifecycle.status": 1, auditVisitedPaths: 1, "lifecycle.closedAt": -1, sessionId: -1 });
    await projection.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });

    const docs = Array.from({ length: sessionCount }, (_, index) => {
      const sessionId = `session-${String(index).padStart(5, "0")}`;
      const homeOnly = index % 4 === 0;
      const path = homeOnly ? "/home/cowrie" : "/etc/passwd";
      return {
        _id: sessionId,
        sessionId,
        sourceIp: `198.51.100.${index % 20}`,
        cwdState: { path, status: "confirmed", observedAt: new Date("2026-09-19T10:00:00.000Z"), sourceEventId: `source-${index}` },
        lifecycle: { status: "closed", closedAt: new Date(2026, 8, 19, 10, 0, Math.floor(index / 2)) },
        auditVisitedPaths: homeOnly ? ["/home/cowrie"] : ["/etc/passwd", "/var/tmp"],
        auditHomeOnly: homeOnly,
        auditEventCount: homeOnly ? 1 : 2,
        auditEventIds: homeOnly ? [`event-${index}`] : [`event-${index}-1`, `event-${index}-2`],
        auditProjectionVersion: AUDIT_PROJECTION_VERSION,
        expires_at: new Date("2099-01-01T00:00:00.000Z"),
      };
    });
    await projection.insertMany(docs, { ordered: true });
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION, backfillCompletedAt: new Date() });

    const productionPathClient = {
      ...client,
      db: (name: string) => name === "honeypot_db" ? database : client.db(name),
    };
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue(productionPathClient as unknown as ReturnType<typeof mongo.getMongoClient>);
  });

  beforeEach(() => aggregateCommands.length = 0);

  afterAll(async () => {
    await database.dropDatabase();
    await client.close();
    vi.restoreAllMocks();
  });

  it("traverses all equal-time pages without duplicates or omissions and never emits skip/lookup", async () => {
    const ids: string[] = [];
    let cursor: string | null = null;
    let pageCount = 0;
    do {
      const page = await getAuditSessions({ limit: 25, cursor });
      ids.push(...page.items.map((item) => item.sessionId));
      cursor = page.nextCursor;
      pageCount += 1;
      expect(page.totalItems).toBe(sessionCount);
      expect(page.items.length).toBeLessThanOrEqual(25);
    } while (cursor !== null);
    expect(pageCount).toBe(Math.ceil(sessionCount / 25));
    expect(ids).toHaveLength(sessionCount);
    expect(new Set(ids).size).toBe(sessionCount);
    expect(ids).toEqual([...ids].sort((left, right) => right.localeCompare(left)));
    expect(aggregateCommands.length).toBe(pageCount);
    for (const command of aggregateCommands) {
      const serialized = JSON.stringify(command.pipeline);
      expect(serialized).not.toContain("$skip");
      expect(serialized).not.toContain("$lookup");
    }
  }, 120_000);

  it("keeps cursor exhaustion and invalid cursor behavior bounded and safe", async () => {
    const first = await getAuditSessions({ limit: 25 });
    expect(first.nextCursor).not.toBeNull();
    const exhausted = await getAuditSessions({ limit: 25, cursor: encodeAuditSessionCursor("2026-09-18T00:00:00.000Z", "session-00000") });
    expect(exhausted.items).toHaveLength(0);
    expect(exhausted.nextCursor).toBeNull();
    const invalid = await getAuditSessions({ limit: 25, cursor: Buffer.from("{}").toString("base64url") });
    expect(invalid.items).toHaveLength(0);
    expect(invalid.totalItems).toBe(sessionCount);
  });

  it("returns authoritative totals, filters, and distinct paths from projection facts", async () => {
    const all = await getAuditDirectorySummary();
    expect(all).toMatchObject({ totalSessions: 1900, homeOnlyCount: 475 });
    expect(all.distinctPaths).toEqual(expect.arrayContaining([
      { path: "/etc/passwd", sessionCount: 1425 },
      { path: "/home/cowrie", sessionCount: 475 },
      { path: "/var/tmp", sessionCount: 1425 },
    ]));

    const hideHome = await getAuditDirectorySummary({ hideHome: true });
    expect(hideHome).toMatchObject({ totalSessions: 1900, homeOnlyCount: 475, matchingCount: 1425 });
    const targetPath = await getAuditSessions({ targetPath: "/etc", limit: 25 });
    expect(targetPath.totalItems).toBe(1425);
    const searchedSession = await getAuditSessions({ search: "session-00017", limit: 25 });
    expect(searchedSession.totalItems).toBe(1);
    expect(searchedSession.items[0]?.sessionId).toBe("session-00017");
    const searchedPath = await getAuditSessions({ search: "/etc/passwd", limit: 25 });
    expect(searchedPath.totalItems).toBe(1425);
    const hiddenPage = await getAuditSessions({ hideHome: true, limit: 25 });
    expect(hiddenPage.totalItems).toBe(1425);
  });

  it("proves page, deep-page, summary, and filtered plans scan projection rows but do no foreign history work", async () => {
    const collection = database.collection("cwd_audit_projection");
    const cases = [
      ["page", buildAuditProjectionSessionsPipeline({ limit: 25 })],
      ["deep", buildAuditProjectionSessionsPipeline({ limit: 25, cursor: encodeAuditSessionCursor("2026-09-19T09:59:00.000Z", "session-00000") })],
      ["summary", buildAuditProjectionSummaryPipeline({})],
      ["filtered", buildAuditProjectionSessionsPipeline({ hideHome: true, targetPath: "/etc", search: "198.51.100.7", limit: 25 })],
    ] as const;
    for (const [label, pipeline] of cases) {
      const explain = await collection.aggregate(pipeline, { allowDiskUse: true }).explain("executionStats");
      const serialized = JSON.stringify(explain);
      expect(serialized).not.toContain("$lookup");
      expect(serialized).not.toContain("COLLSCAN");
      expect(maxMetric(explain, "totalDocsExamined")).toBeLessThanOrEqual(sessionCount);
      expect(maxMetric(explain, "totalKeysExamined")).toBeGreaterThan(0);
      process.stderr.write(`FA016_AFTER ${label} ${JSON.stringify({
        docsExamined: maxMetric(explain, "totalDocsExamined"),
        keysExamined: maxMetric(explain, "totalKeysExamined"),
        nReturned: maxMetric(explain, "nReturned"),
      })}\n`);
    }
  });

  it("keeps the projection retention contract explicit", async () => {
    const indexes = await projection.listIndexes().toArray();
    const ttl = indexes.find((index) => index.key?.expires_at === 1);
    expect(ttl?.expireAfterSeconds).toBe(0);
    const expiredId = "expired-projection";
    await projection.insertOne({ _id: expiredId, sessionId: expiredId, lifecycle: { status: "closed", closedAt: new Date() }, cwdState: { path: "/tmp" }, auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date(Date.now() - 60_000) });
    for (let attempt = 0; attempt < 12; attempt += 1) {
      if (!(await projection.findOne({ _id: expiredId }))) return;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error("projection TTL did not remove the expired document within the isolated test bound");
  }, 15_000);

  it("uses the explicit migration fallback for canonical and legacy source documents", async () => {
    await database.collection("cwd_audit_projection_meta").deleteMany({});
    await database.collection("cwd_session_state").insertMany([
      { _id: "migration-canonical", sessionId: "migration-canonical", sourceIp: "203.0.113.1", cwdState: { path: "/home/cowrie" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-18T00:00:00Z") } },
      { _id: "migration-legacy-state", session_id: "migration-legacy", sourceIp: "203.0.113.2", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-17T00:00:00Z") } },
    ]);
    await database.collection("cwd_events").insertMany([
      { _id: "migration-canonical-event", eventId: "migration-canonical-event", sessionId: "migration-canonical", action: "entered", fromPath: "/home/cowrie", toPath: "/home/cowrie", at: new Date("2026-09-18T00:00:00Z") },
      { _id: "migration-legacy-event", eventId: "migration-legacy-event", session_id: "migration-legacy", action: "changed", fromPath: "/etc", toPath: "/opt", at: new Date("2026-09-17T00:00:00Z") },
    ]);
    const page = await getAuditSessions({ limit: 25 });
    expect(page.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy"]);
    expect(JSON.stringify(aggregateCommands.at(-1)?.pipeline)).toContain("$lookup");
  });
});
