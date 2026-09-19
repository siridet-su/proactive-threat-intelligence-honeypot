import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { MongoClient, type Collection, type Document } from "mongodb";
import {
  buildAuditProjectionCountPipeline,
  buildAuditProjectionItemPipeline,
  buildAuditProjectionSummaryPipeline,
  buildAuditProjectionEventReadinessQuery,
  buildAuditProjectionReadinessQuery,
  encodeAuditSessionCursor,
} from "@/lib/filesystem-data";
import { getAuditDirectorySummary, getAuditSessions, setAuditProjectionReadinessTestHook } from "@/lib/filesystem-server";
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
  const commandEvents: Array<{ commandName: string; command: Document }> = [];
  const sessionCount = 1900;

  beforeAll(async () => {
    client = new MongoClient(target!.uri, { monitorCommands: true });
    client.on("commandStarted", (event) => {
      commandEvents.push({ commandName: event.commandName, command: event.command });
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
    await projection.createIndex({ auditPathsOverflow: 1 });
    await projection.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
    const sourceState = database.collection("cwd_session_state");
    await sourceState.createIndex({ "lifecycle.status": 1, updatedAt: -1, sessionId: -1 });
    await sourceState.createIndex({ "lifecycle.status": 1, "lifecycle.closedAt": -1, sessionId: -1 });
    await sourceState.createIndex({ "lifecycle.status": 1, "lifecycle.closedAt": -1, session_id: -1 });
    await sourceState.createIndex({ "lifecycle.status": 1, auditProjectionVersion: 1 });
    await sourceState.createIndex({ "lifecycle.status": 1, auditProjectionPendingGeneration: 1 }, { partialFilterExpression: { auditProjectionPendingGeneration: { $exists: true } } });
    await sourceState.createIndex({ "cwdState.path": 1 });
    await sourceState.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
    await database.collection("cwd_events").createIndex({ auditProjectionPending: 1, _id: 1 }, { partialFilterExpression: { auditProjectionPending: true } });

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
        auditProjectionVersion: AUDIT_PROJECTION_VERSION,
        expires_at: new Date("2099-01-01T00:00:00.000Z"),
      };
    });
    await projection.insertMany(docs, { ordered: true });
    await database.collection("cwd_session_state").insertMany(docs.map((doc) => ({
      _id: doc._id,
      sessionId: doc.sessionId,
      cwdState: doc.cwdState,
      lifecycle: doc.lifecycle,
      auditProjectionVersion: AUDIT_PROJECTION_VERSION,
      auditProjectionGeneration: 1,
      auditProjectionReadyGeneration: 1,
      expires_at: doc.expires_at,
    })), { ordered: true });
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION, backfillCompletedAt: new Date() });

    const productionPathClient = {
      ...client,
      db: (name: string) => name === "honeypot_db" ? database : client.db(name),
    };
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue(productionPathClient as unknown as ReturnType<typeof mongo.getMongoClient>);
  });

  beforeEach(() => {
    aggregateCommands.length = 0;
    commandEvents.length = 0;
  });

  afterAll(async () => {
    setAuditProjectionReadinessTestHook(null);
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
    expect(aggregateCommands.length).toBe(pageCount * 2);
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

  it("keeps the complete ordinary page request bounded, including readiness", async () => {
    const page = await getAuditSessions({ limit: 25 });
    expect(page.items).toHaveLength(25);
    const readinessFinds = commandEvents.filter(({ commandName, command }) =>
      commandName === "find" && String(command.find).includes("cwd_session_state"));
    expect(readinessFinds.length).toBeGreaterThanOrEqual(2);
    for (const { command } of readinessFinds) {
      const serialized = JSON.stringify(command);
      expect(serialized).not.toContain("$in");
      expect(serialized.length).toBeLessThan(1_000_000);
    }
    // The request has two bounded readiness probes and two bounded projection
    // aggregates; no command contains the retained 1,900-session identifier set.
    expect(JSON.stringify(commandEvents).length).toBeLessThan(2_000_000);
  });

  it("proves readiness execution bounds for converged, pending, stale, and malformed rows", async () => {
    const states = database.collection("cwd_session_state");
    await states.deleteMany({});
    const closedAt = new Date("2026-09-19T10:00:00.000Z");
    await states.insertMany(Array.from({ length: 1900 }, (_, index) => ({
      _id: `ready-${index}`,
      sessionId: `ready-${index}`,
      cwdState: { path: "/etc/passwd" },
      lifecycle: { status: "closed", closedAt },
      auditProjectionVersion: AUDIT_PROJECTION_VERSION,
      auditProjectionGeneration: 1,
      auditProjectionReadyGeneration: 1,
    })));
    const explain = async (query: Document) => states.find(query).project({ _id: 1 }).limit(1).explain("executionStats");
    const steady = await explain(buildAuditProjectionReadinessQuery());
    expect(JSON.stringify(steady)).not.toContain("COLLSCAN");
    expect(maxMetric(steady, "totalDocsExamined")).toBeLessThanOrEqual(1);
    process.stderr.write(`FA016_READINESS steady ${JSON.stringify({ docsExamined: maxMetric(steady, "totalDocsExamined"), keysExamined: maxMetric(steady, "totalKeysExamined") })}\n`);

    const events = database.collection("cwd_events");
    const explainPendingEvents = () => events.find(buildAuditProjectionEventReadinessQuery()).project({ _id: 1 }).limit(1).explain("executionStats");
    const noPendingEvents = await explainPendingEvents();
    expect(JSON.stringify(noPendingEvents)).not.toContain("COLLSCAN");
    expect(maxMetric(noPendingEvents, "totalDocsExamined")).toBeLessThanOrEqual(1);
    await events.insertMany([
      { _id: "pending-explain-1", sessionId: "ready-1", auditProjectionPending: true },
    ]);
    const onePendingEvent = await explainPendingEvents();
    expect(JSON.stringify(onePendingEvent)).not.toContain("COLLSCAN");
    expect(maxMetric(onePendingEvent, "totalDocsExamined")).toBeLessThanOrEqual(1);
    await events.insertMany([
      { _id: "pending-explain-2", sessionId: "ready-2", auditProjectionPending: true },
      { _id: "pending-explain-3", sessionId: "ready-3", auditProjectionPending: true },
    ]);
    const multiplePendingEvents = await explainPendingEvents();
    expect(JSON.stringify(multiplePendingEvents)).not.toContain("COLLSCAN");
    expect(maxMetric(multiplePendingEvents, "totalDocsExamined")).toBeLessThanOrEqual(1);
    await events.deleteMany({});
    process.stderr.write(`FA016_READINESS events ${JSON.stringify({
      zero: { docsExamined: maxMetric(noPendingEvents, "totalDocsExamined"), keysExamined: maxMetric(noPendingEvents, "totalKeysExamined") },
      one: { docsExamined: maxMetric(onePendingEvent, "totalDocsExamined"), keysExamined: maxMetric(onePendingEvent, "totalKeysExamined") },
      multiple: { docsExamined: maxMetric(multiplePendingEvents, "totalDocsExamined"), keysExamined: maxMetric(multiplePendingEvents, "totalKeysExamined") },
    })}\n`);

    await states.insertOne({
      _id: "pending-v2", sessionId: "pending-v2", cwdState: { path: "/etc/pending" }, lifecycle: { status: "closed", closedAt },
      auditProjectionVersion: AUDIT_PROJECTION_VERSION, auditProjectionGeneration: 2, auditProjectionReadyGeneration: 1, auditProjectionPendingGeneration: 2,
    });
    const pending = await explain(buildAuditProjectionReadinessQuery());
    expect(JSON.stringify(pending)).not.toContain("COLLSCAN");
    expect(maxMetric(pending, "totalDocsExamined")).toBeLessThanOrEqual(2);
    process.stderr.write(`FA016_READINESS pending-v2 ${JSON.stringify({ docsExamined: maxMetric(pending, "totalDocsExamined"), keysExamined: maxMetric(pending, "totalKeysExamined") })}\n`);

    await states.insertOne({
      _id: "stale-version", sessionId: "stale-version", cwdState: { path: "/etc/stale" }, lifecycle: { status: "closed", closedAt },
      auditProjectionVersion: "cwd_audit_projection.v1", auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1,
    });
    const stale = await explain(buildAuditProjectionReadinessQuery({ includeVersionMigration: true }));
    expect(JSON.stringify(stale)).not.toContain("COLLSCAN");
    expect(maxMetric(stale, "totalDocsExamined")).toBeLessThanOrEqual(1905);
    process.stderr.write(`FA016_READINESS stale-version ${JSON.stringify({ docsExamined: maxMetric(stale, "totalDocsExamined"), keysExamined: maxMetric(stale, "totalKeysExamined") })}\n`);

    await states.insertOne({
      _id: "malformed", sessionId: "   ", cwdState: { path: "relative" }, lifecycle: { status: "closed", closedAt },
      auditProjectionVersion: "cwd_audit_projection.v1", auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1, auditProjectionPendingGeneration: 1,
    });
    const malformed = await explain(buildAuditProjectionReadinessQuery());
    expect(JSON.stringify(malformed)).not.toContain("COLLSCAN");
    process.stderr.write(`FA016_READINESS malformed ${JSON.stringify({ docsExamined: maxMetric(malformed, "totalDocsExamined"), keysExamined: maxMetric(malformed, "totalKeysExamined") })}\n`);

    commandEvents.length = 0;
    await getAuditSessions({ limit: 25 });
    // The converged request still performs the bounded indexed pending-marker
    // existence probe; it must not run an authoritative history aggregation.
    expect(commandEvents.some(({ commandName, command }) => commandName === "aggregate" && command.aggregate === "cwd_events")).toBe(false);

    // Restore the deterministic 1,900-row source fixture for the following
    // projection-summary cases; this test intentionally exercises its own
    // readiness population.
    const baselineProjectionRows = await projection.find({}).toArray();
    await states.deleteMany({});
    await states.insertMany(baselineProjectionRows.map((row) => ({
      _id: row._id,
      sessionId: row.sessionId,
      sourceIp: row.sourceIp,
      cwdState: row.cwdState,
      lifecycle: row.lifecycle,
      auditProjectionVersion: AUDIT_PROJECTION_VERSION,
      auditProjectionGeneration: 1,
      auditProjectionReadyGeneration: 1,
      expires_at: row.expires_at,
    })));
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
    const searchedIp = await getAuditSessions({ search: "198.51.100.7", limit: 25 });
    expect(searchedIp.totalItems).toBe(95);
    const hiddenPage = await getAuditSessions({ hideHome: true, limit: 25 });
    expect(hiddenPage.totalItems).toBe(1425);
  });

  it("reports item, count, summary, and filtered plans separately with truthful bounds", async () => {
    const collection = database.collection("cwd_audit_projection");
    const cases = [
      ["item", buildAuditProjectionItemPipeline({ limit: 25 })],
      ["deep-item", buildAuditProjectionItemPipeline({ limit: 25, cursor: encodeAuditSessionCursor("2026-09-19T10:07:00.000Z", "session-00000") })],
      ["count", buildAuditProjectionCountPipeline({})],
      ["summary", buildAuditProjectionSummaryPipeline({})],
      ["filtered-item", buildAuditProjectionItemPipeline({ hideHome: true, targetPath: "/etc", search: "198.51.100.7", limit: 25 })],
      ["filtered-count", buildAuditProjectionCountPipeline({ hideHome: true, targetPath: "/etc", search: "198.51.100.7", limit: 25 })],
    ] as const;
    for (const [label, pipeline] of cases) {
      const explain = await collection.aggregate(pipeline, { allowDiskUse: true }).explain("executionStats");
      const serialized = JSON.stringify(explain);
      expect(serialized).not.toContain("$lookup");
      expect(serialized).not.toContain("COLLSCAN");
      const docsExamined = maxMetric(explain, "totalDocsExamined");
      if (label === "item" || label === "deep-item") expect(docsExamined).toBeLessThanOrEqual(100);
      else expect(docsExamined).toBeLessThanOrEqual(sessionCount);
      expect(maxMetric(explain, "totalKeysExamined")).toBeGreaterThan(0);
      process.stderr.write(`FA016_AFTER ${label} ${JSON.stringify({
        docsExamined,
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
    await Promise.all([
      database.collection("cwd_session_state").deleteMany({}),
      database.collection("cwd_events").deleteMany({}),
      projection.deleteMany({}),
      database.collection("cwd_audit_projection_meta").deleteMany({}),
    ]);
    await database.collection("cwd_session_state").insertMany([
      { _id: "migration-canonical", sessionId: "migration-canonical", sourceIp: "203.0.113.1", cwdState: { path: "/home/cowrie" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-18T00:00:00Z") } },
      { _id: "migration-legacy-state", session_id: "migration-legacy", sourceIp: "203.0.113.2", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-17T00:00:00Z") } },
    ]);
    await database.collection("cwd_events").insertMany([
      { _id: "migration-canonical-event", eventId: "migration-canonical-event", sessionId: "migration-canonical", action: "entered", fromPath: "/home/cowrie", toPath: "/home/cowrie", at: new Date("2026-09-18T00:00:00Z") },
      { _id: "migration-legacy-event", eventId: "migration-legacy-event", session_id: "migration-legacy", action: "changed", fromPath: "/etc", toPath: "/opt", at: new Date("2026-09-17T00:00:00Z") },
    ]);
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: "cwd_audit_projection.v1" });
    const oldMarkerPage = await getAuditSessions({ limit: 25 });
    expect(oldMarkerPage.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy"]);
    expect(JSON.stringify(aggregateCommands.at(-1)?.pipeline)).toContain("$lookup");
    await database.collection("cwd_audit_projection_meta").deleteMany({});
    const page = await getAuditSessions({ limit: 25 });
    expect(page.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy"]);
    expect(JSON.stringify(aggregateCommands.at(-1)?.pipeline)).toContain("$lookup");

    // An old rolling writer can publish a closed source row after the marker.
    // These fixtures intentionally have no generation/pending fields at all;
    // the separate cutover probe must force the authoritative fallback rather
    // than silently dropping either canonical or legacy-schema row.
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION });
    await database.collection("cwd_events").insertOne({ _id: "readiness-pending-event", eventId: "readiness-pending-event", sessionId: "migration-canonical", action: "changed", fromPath: "/home/cowrie", toPath: "/etc", at: new Date("2026-09-18T00:00:01Z"), auditProjectionPending: true });
    const pendingMarkerPage = await getAuditSessions({ limit: 25 });
    expect(pendingMarkerPage.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy"]);
    expect(JSON.stringify(aggregateCommands.at(-1)?.pipeline)).toContain("$lookup");
    await database.collection("cwd_events").deleteOne({ _id: "readiness-pending-event" });
    let insertedByOldWriter = false;
    setAuditProjectionReadinessTestHook(async () => {
      if (insertedByOldWriter) return;
      insertedByOldWriter = true;
      await database.collection("cwd_session_state").insertMany([
        { _id: "migration-old-writer", sessionId: "migration-old-writer", sourceIp: "203.0.113.9", cwdState: { path: "/home/cowrie" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-16T00:00:00Z") } },
        { _id: "migration-old-legacy", session_id: "migration-old-legacy", sourceIp: "203.0.113.10", cwdState: { path: "/var/tmp" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-15T00:00:00Z") } },
      ]);
    });
    const rollingPage = await getAuditSessions({ limit: 25 });
    setAuditProjectionReadinessTestHook(null);
    expect(rollingPage.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy", "migration-old-writer", "migration-old-legacy"]);
    expect(JSON.stringify(aggregateCommands.at(-1)?.pipeline)).toContain("$lookup");

    // Model the processor's exact v2 convergence for both old-writer rows and
    // prove the next production read is projection-backed without a history
    // collection read.
    await projection.insertMany([
      { _id: "migration-canonical", sessionId: "migration-canonical", sourceIp: "203.0.113.1", cwdState: { path: "/home/cowrie" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-18T00:00:00Z") }, auditVisitedPaths: ["/home/cowrie"], auditHomeOnly: true, auditEventCount: 0, auditProjectionVersion: AUDIT_PROJECTION_VERSION },
      { _id: "migration-legacy", sessionId: "migration-legacy", sourceIp: "203.0.113.2", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-17T00:00:00Z") }, auditVisitedPaths: ["/etc"], auditHomeOnly: false, auditEventCount: 0, auditProjectionVersion: AUDIT_PROJECTION_VERSION },
      { _id: "migration-old-writer", sessionId: "migration-old-writer", sourceIp: "203.0.113.9", cwdState: { path: "/home/cowrie" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-16T00:00:00Z") }, auditVisitedPaths: ["/home/cowrie"], auditHomeOnly: true, auditEventCount: 0, auditProjectionVersion: AUDIT_PROJECTION_VERSION },
      { _id: "migration-old-legacy", sessionId: "migration-old-legacy", sourceIp: "203.0.113.10", cwdState: { path: "/var/tmp" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-15T00:00:00Z") }, auditVisitedPaths: ["/var/tmp"], auditHomeOnly: false, auditEventCount: 0, auditProjectionVersion: AUDIT_PROJECTION_VERSION },
    ]);
    await database.collection("cwd_session_state").updateMany({}, { $set: { auditProjectionVersion: AUDIT_PROJECTION_VERSION, auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1 } });
    commandEvents.length = 0;
    const convergedPage = await getAuditSessions({ limit: 25 });
    expect(convergedPage.items.map((item) => item.sessionId)).toEqual(["migration-canonical", "migration-legacy", "migration-old-writer", "migration-old-legacy"]);
    expect(commandEvents.some(({ commandName, command }) => commandName === "aggregate" && command.aggregate === "cwd_events")).toBe(false);
  });

  it("keeps overflow exact and scoped to its session while normal pages stay projection-backed", async () => {
    await Promise.all([
      database.collection("cwd_session_state").deleteMany({}),
      database.collection("cwd_events").deleteMany({}),
      projection.deleteMany({}),
      database.collection("cwd_audit_projection_meta").deleteMany({}),
    ]);
    const closedAt = new Date("2026-09-19T23:00:00.000Z");
    await projection.insertMany([
      {
        _id: "normal-session", sessionId: "normal-session", sourceIp: "198.51.100.40",
        cwdState: { path: "/var/normal", status: "confirmed" }, lifecycle: { status: "closed", closedAt },
        auditVisitedPaths: ["/var/normal"], auditHomeOnly: false, auditEventCount: 1,
        auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z"),
      },
      {
        _id: "overflow-session", sessionId: "overflow-session", sourceIp: "198.51.100.41",
        cwdState: { path: "/overflow/619", status: "confirmed" }, lifecycle: { status: "closed", closedAt: new Date(closedAt.getTime() - 1_000) },
        auditVisitedPaths: Array.from({ length: 512 }, (_, index) => `/overflow/${index}`),
        auditTransitionPaths: Array.from({ length: 512 }, (_, index) => `/overflow/${index}`),
        auditPathsOverflow: true, auditHomeOnly: false, auditEventCount: 620,
        auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z"),
      },
    ]);
    await database.collection("cwd_session_state").insertOne({
      _id: "overflow-session", sessionId: "overflow-session", sourceIp: "198.51.100.41",
      cwdState: { path: "/overflow/619", status: "confirmed" }, lifecycle: { status: "closed", closedAt: new Date(closedAt.getTime() - 1_000) },
      auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z"),
    });
    await database.collection("cwd_events").insertMany(Array.from({ length: 620 }, (_, index) => ({
      _id: `overflow-event-${index}`, eventId: `overflow-event-${index}`, sessionId: "overflow-session", action: "changed",
      fromPath: `/overflow/${index}`, toPath: `/overflow/${index + 1}`, at: closedAt,
    })));
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION, backfillCompletedAt: new Date() });

    const page = await getAuditSessions({ limit: 25 });
    expect(page.totalItems).toBe(2);
    const overflowItem = page.items.find((item) => item.sessionId === "overflow-session");
    expect(overflowItem?.auditSummary.visitedPaths).toContain("/overflow/619");
    expect(overflowItem?.auditSummary.visitedPaths.length).toBeGreaterThan(512);
    expect(aggregateCommands.some((command) => JSON.stringify(command.pipeline).includes("$unionWith"))).toBe(true);

    const exact = await getAuditSessions({ targetPath: "/overflow/619", limit: 25 });
    expect(exact.totalItems).toBe(1);
    expect(exact.items.map((item) => item.sessionId)).toEqual(["overflow-session"]);
    const summary = await getAuditDirectorySummary({ targetPath: "/overflow/619" });
    expect(summary.matchingCount).toBe(1);
    expect((await projection.findOne({ _id: "overflow-session" }))?.auditVisitedPaths).toHaveLength(512);
  });

  it("traverses a mixed multi-page overflow population exactly once with all filters", async () => {
    await Promise.all([
      database.collection("cwd_session_state").deleteMany({}),
      database.collection("cwd_events").deleteMany({}),
      projection.deleteMany({}),
      database.collection("cwd_audit_projection_meta").deleteMany({}),
    ]);
    const closedAt = new Date("2026-09-19T23:30:00.000Z");
    const sourceStates: Document[] = [];
    const history: Document[] = [];
    const projectionDocs: Document[] = [];
    for (let index = 0; index < 80; index += 1) {
      const sessionId = `mixed-${String(index).padStart(3, "0")}`;
      const overflow = index % 2 === 0;
      const homeOnly = index === 2;
      const currentPath = homeOnly ? "/home/cowrie" : `/var/current-${index}`;
      const visitedPaths = homeOnly ? ["/home/cowrie"] : [currentPath, "/etc/passwd"];
      sourceStates.push({
        _id: sessionId, sessionId, sourceIp: `203.0.113.${index}`,
        cwdState: { path: currentPath, status: "confirmed" }, lifecycle: { status: "closed", closedAt },
        auditProjectionVersion: AUDIT_PROJECTION_VERSION,
        auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1,
        expires_at: new Date("2099-01-01T00:00:00Z"),
      });
      if (overflow) {
        history.push({
          _id: `${sessionId}-target`, eventId: `${sessionId}-target`, sessionId, action: "changed",
          fromPath: homeOnly ? "/home/cowrie" : `/overflow-target/${index}`, toPath: currentPath, at: closedAt,
        });
      }
      projectionDocs.push({
        _id: sessionId, sessionId, sourceIp: `203.0.113.${index}`,
        cwdState: { path: currentPath, status: "confirmed" }, lifecycle: { status: "closed", closedAt },
        auditVisitedPaths: overflow ? Array.from({ length: 512 }, (_, pathIndex) => `/overflow/${index}/${pathIndex}`) : visitedPaths,
        auditTransitionPaths: overflow ? Array.from({ length: 512 }, (_, pathIndex) => `/overflow/${index}/${pathIndex}`) : visitedPaths,
        auditPathsOverflow: overflow, auditHomeOnly: homeOnly, auditEventCount: overflow ? 1 : 0,
        auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z"),
      });
    }
    await database.collection("cwd_session_state").insertMany(sourceStates);
    await database.collection("cwd_events").insertMany(history);
    await projection.insertMany(projectionDocs);
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION, backfillCompletedAt: new Date() });

    const ids: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page = await getAuditSessions({ limit: 25, cursor });
      expect(page.totalItems).toBe(80);
      ids.push(...page.items.map((item) => item.sessionId));
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor !== null);
    expect(pages).toBe(4);
    expect(ids).toHaveLength(80);
    expect(new Set(ids).size).toBe(80);
    expect(ids).toEqual([...ids].sort((left, right) => right.localeCompare(left)));
    expect(aggregateCommands.some((command) => JSON.stringify(command.pipeline).includes("$unionWith"))).toBe(true);

    const olderOverflow = await getAuditSessions({ targetPath: "/overflow-target/0", limit: 25 });
    expect(olderOverflow.totalItems).toBe(1);
    expect(olderOverflow.items.map((item) => item.sessionId)).toEqual(["mixed-000"]);
    expect((await getAuditSessions({ search: "mixed-000", limit: 25 })).items.map((item) => item.sessionId)).toEqual(["mixed-000"]);
    expect((await getAuditSessions({ hideHome: true, limit: 100 })).totalItems).toBe(79);
    expect((await getAuditDirectorySummary({ targetPath: "/overflow-target/0" })).matchingCount).toBe(1);

    await projection.updateMany({}, { $set: { auditPathsOverflow: false } });
    aggregateCommands.length = 0;
    await getAuditSessions({ limit: 25 });
    expect(aggregateCommands.length).toBe(2);
    for (const command of aggregateCommands) {
      expect(JSON.stringify(command.pipeline)).not.toContain("$lookup");
      expect(JSON.stringify(command.pipeline)).not.toContain("$unionWith");
    }
  }, 120_000);

  it("computes the global top 100 after combining overflow populations", async () => {
    await Promise.all([
      database.collection("cwd_session_state").deleteMany({}),
      database.collection("cwd_events").deleteMany({}),
      projection.deleteMany({}),
      database.collection("cwd_audit_projection_meta").deleteMany({}),
    ]);
    const closedAt = new Date("2026-09-19T23:00:00.000Z");
    const competitors = Array.from({ length: 101 }, (_, index) => `/competing/${String(index).padStart(3, "0")}`);
    const sourceStates: Document[] = [];
    const history: Document[] = [];
    const projectionDocs: Document[] = [];
    for (const population of ["projection", "overflow"]) {
      for (const path of competitors.map((value) => `/${population}-${value.slice(1)}`)) {
        for (let index = 0; index < 5; index += 1) {
          const sessionId = `${population}-${path.slice(path.lastIndexOf("/") + 1)}-${index}`;
          sourceStates.push({ _id: sessionId, sessionId, cwdState: { path }, lifecycle: { status: "closed", closedAt }, auditProjectionVersion: AUDIT_PROJECTION_VERSION, auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1, expires_at: new Date("2099-01-01T00:00:00Z") });
          history.push({ _id: `${sessionId}-event`, eventId: `${sessionId}-event`, sessionId, action: "entered", fromPath: path, toPath: path, at: closedAt });
          projectionDocs.push({ _id: sessionId, sessionId, cwdState: { path }, lifecycle: { status: "closed", closedAt }, auditVisitedPaths: [path], auditTransitionPaths: [path], auditPathsOverflow: population === "overflow", auditHomeOnly: false, auditEventCount: 1, auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z") });
        }
      }
    }
    for (const population of ["projection", "overflow"]) {
      for (let index = 0; index < 4; index += 1) {
        const sessionId = `${population}-target-${index}`;
        const path = "/globally-top";
        sourceStates.push({ _id: sessionId, sessionId, cwdState: { path }, lifecycle: { status: "closed", closedAt }, auditProjectionVersion: AUDIT_PROJECTION_VERSION, auditProjectionGeneration: 1, auditProjectionReadyGeneration: 1, expires_at: new Date("2099-01-01T00:00:00Z") });
        history.push({ _id: `${sessionId}-event`, eventId: `${sessionId}-event`, sessionId, action: "entered", fromPath: path, toPath: path, at: closedAt });
        projectionDocs.push({ _id: sessionId, sessionId, cwdState: { path }, lifecycle: { status: "closed", closedAt }, auditVisitedPaths: [path], auditTransitionPaths: [path], auditPathsOverflow: population === "overflow", auditHomeOnly: false, auditEventCount: 1, auditProjectionVersion: AUDIT_PROJECTION_VERSION, expires_at: new Date("2099-01-01T00:00:00Z") });
      }
    }
    await database.collection("cwd_session_state").insertMany(sourceStates);
    await database.collection("cwd_events").insertMany(history);
    await projection.insertMany(projectionDocs);
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: AUDIT_PROJECTION_VERSION, backfillCompletedAt: new Date() });

    const summary = await getAuditDirectorySummary();
    expect(summary.distinctPaths[0]).toEqual({ path: "/globally-top", sessionCount: 8 });
    expect(summary.distinctPaths).not.toContainEqual({ path: "/projection-competing/000", sessionCount: 5 });
  });

  it("applies the same valid-row and canonical identifier contract to source fallback", async () => {
    await Promise.all([
      database.collection("cwd_session_state").deleteMany({}),
      database.collection("cwd_events").deleteMany({}),
      projection.deleteMany({}),
      database.collection("cwd_audit_projection_meta").deleteMany({}),
    ]);
    await database.collection("cwd_session_state").insertMany([
      { _id: "padded", sessionId: "  padded-id  ", cwdState: { path: " /home/cowrie " }, lifecycle: { status: "closed", closedAt: "2026-09-19T23:00:00.000Z" } },
      { _id: "legacy", session_id: " legacy-id ", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: new Date("2026-09-19T22:00:00.000Z") } },
      { _id: "bad-id", sessionId: "   ", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: new Date() } },
      { _id: "bad-date", sessionId: "bad-date", cwdState: { path: "/etc" }, lifecycle: { status: "closed", closedAt: "not-a-date" } },
      { _id: "bad-path", sessionId: "bad-path", cwdState: { path: "relative" }, lifecycle: { status: "closed", closedAt: new Date() } },
      { _id: "active", sessionId: "active", cwdState: { path: "/etc" }, lifecycle: { status: "active", closedAt: new Date() } },
    ]);
    await database.collection("cwd_audit_projection_meta").insertOne({ _id: "audit-directory", projectionVersion: "cwd_audit_projection.v1" });
    const page = await getAuditSessions({ limit: 25 });
    expect(page.items.map((item) => item.sessionId)).toEqual(["padded-id", "legacy-id"]);
  });
});
