import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { MongoClient, ObjectId, type Collection, type Document } from "mongodb";
import {
  buildSessionCwdHistoryPipeline,
  normalizeHistoryEvent,
} from "@/lib/filesystem-data";
import { getSessionCwdHistory, MAX_CWD_IDENTIFIER_LENGTH } from "@/lib/filesystem-server";
import * as mongo from "@/lib/mongodb";

const SESSION_ID = "session-fa-010";
const PAGE_SIZE = 80;

type RawHistoryDocument = Record<string, unknown>;

function eventDocument(overrides: RawHistoryDocument = {}): RawHistoryDocument {
  return {
    _id: "raw-id",
    sessionId: SESSION_ID,
    eventId: "event-id",
    at: "2026-09-18T00:00:00.000Z",
    action: "changed",
    status: "confirmed",
    fromPath: "/",
    toPath: "/tmp",
    ...overrides,
  };
}

function compareNewestFirst(left: SessionCwdHistoryEvent, right: SessionCwdHistoryEvent): number {
  const time = right.at.localeCompare(left.at);
  if (time !== 0) return time;
  if (right.id === left.id) return 0;
  return right.id > left.id ? 1 : -1;
}

function asProjectedDocument(event: SessionCwdHistoryEvent): RawHistoryDocument {
  return {
    sessionId: event.sessionId,
    eventId: event.id,
    at: new Date(event.at),
    sequence: event.sequence,
    fromPath: event.fromPath,
    toPath: event.toPath,
    action: event.action,
    status: event.status,
    sourceEventId: event.sourceEventId,
  };
}

function installFacetResponseMock(rawDocuments: RawHistoryDocument[]) {
  const aggregate = vi.fn().mockImplementation((pipeline: Array<Record<string, unknown>>) => {
    const facet = pipeline.at(-1)?.$facet as Record<string, unknown>;
    const itemPipeline = facet.items as Array<Record<string, unknown>>;
    const pageLimit = (itemPipeline.find((stage) => "$limit" in stage)?.$limit as number) ?? PAGE_SIZE + 1;
    const valid = rawDocuments
      .map(normalizeHistoryEvent)
      .filter((event): event is SessionCwdHistoryEvent => event?.sessionId === SESSION_ID)
      .sort(compareNewestFirst);

    const cursorStage = itemPipeline.find((stage) => "$match" in stage) as {
      $match?: { $or?: Array<Record<string, unknown>> };
    } | undefined;
    const cursorOr = cursorStage?.$match?.$or;
    const cursorAt = cursorOr?.[0]?.at as { $lt?: Date } | undefined;
    const cursorId = cursorOr?.[1]?.eventId as { $lt?: string } | undefined;
    const afterCursor = cursorAt?.$lt && cursorId?.$lt
      ? valid.filter((event) => event.at < cursorAt.$lt!.toISOString() || (event.at === cursorAt.$lt!.toISOString() && event.id < cursorId.$lt!))
      : valid;

    return {
      toArray: vi.fn().mockResolvedValue([{
        items: afterCursor.slice(0, pageLimit).map(asProjectedDocument),
        totalItems: [{ count: valid.length }],
        totalSuccessfulItems: [{ count: valid.filter((event) => event.action !== "failed_change").length }],
      }]),
    };
  });

  vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
    db: () => ({ collection: () => ({ aggregate }) }),
  } as unknown as ReturnType<typeof mongo.getMongoClient>);
  return aggregate;
}

function malformedDocuments(): RawHistoryDocument[] {
  return [
    eventDocument({ _id: "bad-action", action: "not-supported" }),
    eventDocument({ _id: "bad-date", eventId: "bad-date", at: "not-a-date" }),
    eventDocument({ _id: "bad-session", eventId: "bad-session", sessionId: "other-session" }),
    eventDocument({ _id: "", eventId: "   " }),
    eventDocument({ _id: "   ", eventId: "   " }),
    eventDocument({ _id: "bad-time-type", eventId: "bad-time-type", at: 1234 }),
  ];
}

function validEvent(index: number, overrides: RawHistoryDocument = {}): RawHistoryDocument {
  return eventDocument({
    _id: `raw-${index}`,
    eventId: `event-${String(index).padStart(3, "0")}`,
    at: new Date(Date.UTC(2026, 8, 18, 0, 0, index)).toISOString(),
    ...overrides,
  });
}

describe("FA-010 application history facet decoding", () => {
  it("filters malformed records before page limiting, preserves lookahead, and counts the same valid population", async () => {
    const raw = [
      ...malformedDocuments(),
      ...Array.from({ length: PAGE_SIZE + 1 }, (_, index) => validEvent(index)),
      validEvent(PAGE_SIZE + 1, { action: "failed_change" }),
      ...malformedDocuments(),
    ];
    const aggregate = installFacetResponseMock(raw);

    const page = await getSessionCwdHistory(SESSION_ID, null);

    expect(page.items).toHaveLength(PAGE_SIZE);
    expect(page.items.every((event) => event.id.startsWith("event-"))).toBe(true);
    expect(page.totalItems).toBe(PAGE_SIZE + 2);
    expect(page.totalSuccessfulItems).toBe(PAGE_SIZE + 1);
    expect(page.complete).toBe(false);
    expect(page.nextCursor).not.toBeNull();
    expect(aggregate).toHaveBeenCalledOnce();
    expect(aggregate.mock.calls[0]?.[1]).toEqual({ allowDiskUse: true });
  });

  it("keeps valid events after malformed raw lookahead reachable and ends exactly at the valid tail", async () => {
    const raw = [
      ...Array.from({ length: PAGE_SIZE }, (_, index) => validEvent(index)),
      ...malformedDocuments(),
      validEvent(PAGE_SIZE),
    ];
    installFacetResponseMock(raw);

    const first = await getSessionCwdHistory(SESSION_ID, null);
    const second = await getSessionCwdHistory(SESSION_ID, first.nextCursor);

    expect(first.nextCursor).not.toBeNull();
    expect(first.complete).toBe(false);
    expect(second.items).toHaveLength(1);
    expect(second.items[0]?.id).toBe("event-000");
    expect(second.nextCursor).toBeNull();
    expect(second.complete).toBe(true);
    expect([...first.items, ...second.items].map((event) => event.id)).toHaveLength(PAGE_SIZE + 1);
  });

  it("uses canonical and legacy session, timestamp, and identifier fallbacks in one deterministic order", async () => {
    const raw = [
      eventDocument({ _id: "canonical-fallback", eventId: "canonical-id", at: "2026-09-18T00:00:00.000Z" }),
      {
        _id: "legacy-id-z",
        session_id: SESSION_ID,
        timestamp: "2026-09-18T00:00:00.000Z",
        action: "entered",
        status: "observed",
      },
      {
        _id: "legacy-id-a",
        session_id: SESSION_ID,
        timestamp: "2026-09-17T23:59:59.000Z",
        action: "changed",
        status: "confirmed",
      },
    ];
    installFacetResponseMock(raw);

    const page = await getSessionCwdHistory(SESSION_ID, null);

    expect(page.items.map((event) => event.id)).toEqual(["legacy-id-z", "canonical-id", "legacy-id-a"]);
    expect(page.items.map((event) => event.sessionId)).toEqual([SESSION_ID, SESSION_ID, SESSION_ID]);
    expect(page.totalItems).toBe(3);
  });

  it("uses eventId as the same-timestamp tie-breaker and traverses without duplicates or omissions", async () => {
    const raw = [
      validEvent(1, { at: "2026-09-18T00:00:00.000Z", eventId: "event-b" }),
      validEvent(2, { at: "2026-09-18T00:00:00.000Z", eventId: "event-a" }),
      ...Array.from({ length: PAGE_SIZE - 1 }, (_, index) => validEvent(index + 3)),
      ...Array.from({ length: 3 }, (_, index) => validEvent(index + PAGE_SIZE + 3)),
    ];
    installFacetResponseMock(raw);

    const pages: SessionCwdHistoryEvent[] = [];
    let cursor: string | null = null;
    do {
      const page = await getSessionCwdHistory(SESSION_ID, cursor);
      pages.push(...page.items);
      cursor = page.nextCursor;
      expect(page.complete).toBe(cursor === null);
    } while (cursor !== null);

    const ids = pages.map((event) => event.id);
    expect(ids).toHaveLength(new Set(ids).size);
    expect(ids).toHaveLength(raw.length);
    expect(ids.indexOf("event-b")).toBeLessThan(ids.indexOf("event-a"));
  });

  it("returns truthful zero totals and complete pagination when every record is malformed", async () => {
    installFacetResponseMock(malformedDocuments());

    const page = await getSessionCwdHistory(SESSION_ID, null);

    expect(page).toEqual({
      items: [],
      nextCursor: null,
      totalItems: 0,
      totalSuccessfulItems: 0,
      complete: true,
    });
  });

  it("keeps bounded invalid-identifier behavior and checks the facet shape without Mongo execution", async () => {
    const aggregate = installFacetResponseMock([validEvent(1)]);
    const overlength = await getSessionCwdHistory("x".repeat(MAX_CWD_IDENTIFIER_LENGTH + 1), null);
    expect(overlength).toEqual({ items: [], nextCursor: null, totalItems: 0, totalSuccessfulItems: 0, complete: true });
    expect(aggregate).not.toHaveBeenCalled();

    const pipeline = buildSessionCwdHistoryPipeline(SESSION_ID, null, PAGE_SIZE);
    expect(pipeline[0]).toEqual({ $match: { $or: [{ sessionId: SESSION_ID }, { session_id: SESSION_ID }] } });
    const facet = pipeline.at(-1)?.$facet as Record<string, Array<Record<string, unknown>>>;
    expect(facet.items).toContainEqual({ $limit: PAGE_SIZE + 1 });
    expect(facet.totalItems).toContainEqual({ $count: "count" });
    expect(facet.totalSuccessfulItems).toContainEqual({ $match: { action: { $ne: "failed_change" } } });
  });
});

const integrationUri = process.env.FA010_MONGO_URI;
const describeMongoIntegration = integrationUri ? describe : describe.skip;

describeMongoIntegration("FA-010 MongoDB aggregation integration", () => {
  let client: MongoClient;
  let collection: Collection<Document>;
  const aggregateCommands: Document[] = [];

  beforeAll(async () => {
    client = new MongoClient(integrationUri!, { monitorCommands: true });
    client.on("commandStarted", (event) => {
      if (event.commandName === "aggregate" && event.command.aggregate === "cwd_events") {
        aggregateCommands.push(event.command);
      }
    });
    await client.connect();
    collection = client.db("honeypot_db").collection("cwd_events");
    await collection.deleteMany({});
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue(client as unknown as ReturnType<typeof mongo.getMongoClient>);
  });

  beforeEach(async () => {
    await collection.deleteMany({});
    aggregateCommands.length = 0;
  });

  afterAll(async () => {
    await collection.drop();
    await client.close();
    vi.restoreAllMocks();
  });

  async function seed(documents: Document[]): Promise<void> {
    if (documents.length) await collection.insertMany(documents, { ordered: true });
  }

  function canonicalEvent(index: number, action: "entered" | "changed" | "failed_change" = "changed"): Document {
    const eventId = index === 82 ? "tie-z" : index === 83 ? "tie-a" : `event-${String(index).padStart(3, "0")}`;
    return {
      _id: `canonical-${index}`,
      sessionId: SESSION_ID,
      eventId,
      at: index >= 82 ? new Date("2026-09-18T00:10:00.000Z") : new Date(Date.UTC(2026, 8, 18, 0, 0, index)),
      action,
      status: action === "failed_change" ? "conditional_candidate" : "confirmed",
      sequence: String(index),
      fromPath: "/",
      toPath: `/tmp/${index}`,
      sourceEventId: `source-${index}`,
    };
  }

  it("executes the exact production pipeline and proves valid legacy fallback, parity, totals, and pagination", async () => {
    const legacyObjectId = new ObjectId("507f1f77bcf86cd799439011");
    const legacyStringId = "legacy-invalid-canonical-fields";
    const documents: Document[] = [
      {
        _id: "malformed-before-page",
        sessionId: SESSION_ID,
        eventId: "malformed-before-page",
        at: "not-a-date",
        timestamp: 1234,
        action: "changed",
      },
      {
        _id: "",
        sessionId: SESSION_ID,
        eventId: "   ",
        at: new Date("2026-09-18T00:20:00.000Z"),
        action: "changed",
      },
      {
        _id: "malformed-unsupported-action",
        sessionId: SESSION_ID,
        eventId: "malformed-unsupported-action",
        at: new Date("2026-09-18T00:21:00.000Z"),
        action: "deleted",
      },
      {
        _id: "   ",
        sessionId: SESSION_ID,
        eventId: "   ",
        at: new Date("2026-09-18T00:22:00.000Z"),
        action: "changed",
      },
      {
        _id: "wrong-session",
        session_id: "other-session",
        eventId: "wrong-session",
        timestamp: new Date("2026-09-18T00:23:00.000Z"),
        action: "changed",
      },
      {
        _id: legacyObjectId,
        session_id: SESSION_ID,
        eventId: "   ",
        at: "invalid-canonical-at",
        timestamp: "2026-09-18T00:30:00.000Z",
        action: "entered",
        status: "observed",
      },
      {
        _id: legacyStringId,
        sessionId: "   ",
        session_id: SESSION_ID,
        eventId: "   ",
        at: "invalid-canonical-at",
        timestamp: new Date("2026-09-18T00:29:00.000Z"),
        action: "changed",
        status: "confirmed",
      },
      {
        _id: "canonical-precedence-fallback",
        sessionId: SESSION_ID,
        session_id: "other-session",
        eventId: "canonical-precedence",
        at: new Date("2026-09-18T00:28:00.000Z"),
        timestamp: new Date("2026-09-17T00:00:00.000Z"),
        action: "changed",
        status: "confirmed",
      },
    ];
    for (let index = 0; index < 84; index += 1) {
      if (index % 9 === 0) {
        documents.push({
          _id: `malformed-inside-${index}`,
          sessionId: SESSION_ID,
          eventId: `malformed-inside-${index}`,
          at: "invalid",
          action: "changed",
        });
      }
      documents.push(canonicalEvent(index, index === 81 ? "failed_change" : "changed"));
    }
    documents.push({
      _id: "malformed-retained-tail",
      sessionId: SESSION_ID,
      eventId: "malformed-retained-tail",
      at: new Date("2026-09-01T00:00:00.000Z"),
      action: "unsupported",
    });
    await seed(documents);

    const first = await getSessionCwdHistory(SESSION_ID, null);
    expect(aggregateCommands).toHaveLength(1);
    expect(aggregateCommands[0]?.pipeline).toEqual(buildSessionCwdHistoryPipeline(SESSION_ID, null, PAGE_SIZE));
    expect(first.items).toHaveLength(PAGE_SIZE);
    expect(first.nextCursor).not.toBeNull();
    expect(first.complete).toBe(false);
    expect(first.totalItems).toBe(87);
    expect(first.totalSuccessfulItems).toBe(86);
    expect(first.items.some((item) => item.id === legacyObjectId.toHexString())).toBe(true);
    expect(first.items.some((item) => item.id === legacyStringId)).toBe(true);
    expect(first.items.some((item) => item.id === "canonical-precedence")).toBe(true);
    expect(first.items.map((item) => item.id)).not.toContain("malformed-before-page");
    expect(first.items.map((item) => item.id)).not.toContain("malformed-unsupported-action");

    const second = await getSessionCwdHistory(SESSION_ID, first.nextCursor);
    expect(aggregateCommands).toHaveLength(2);
    expect(aggregateCommands[1]?.pipeline).toEqual(buildSessionCwdHistoryPipeline(SESSION_ID, first.nextCursor, PAGE_SIZE));
    expect(second.items).toHaveLength(7);
    expect(second.nextCursor).toBeNull();
    expect(second.complete).toBe(true);
    expect(second.totalItems).toBe(87);
    expect(second.totalSuccessfulItems).toBe(86);

    const allItems = [...first.items, ...second.items];
    expect(new Set(allItems.map((item) => item.id)).size).toBe(87);
    expect(allItems.findIndex((item) => item.id === "tie-z")).toBeLessThan(allItems.findIndex((item) => item.id === "tie-a"));
    for (const item of allItems) {
      expect(normalizeHistoryEvent({ ...item, eventId: item.id, at: new Date(item.at) })).not.toBeNull();
    }

    const rawFacet = await collection.aggregate(buildSessionCwdHistoryPipeline(SESSION_ID, null, PAGE_SIZE)).next();
    expect(rawFacet?.items).toHaveLength(PAGE_SIZE + 1);
    expect((rawFacet?.items as Document[]).every((item) => normalizeHistoryEvent(item) !== null)).toBe(true);
    expect((rawFacet?.items as Document[]).some((item) => item.eventId === "malformed-before-page")).toBe(false);
  });

  it("returns zero valid totals and complete pagination for an all-malformed isolated collection", async () => {
    await seed([
      { _id: "bad-action", sessionId: SESSION_ID, eventId: "bad-action", at: new Date(), action: "unsupported" },
      { _id: "bad-date", sessionId: SESSION_ID, eventId: "bad-date", at: "invalid", action: "changed" },
      { _id: "", sessionId: SESSION_ID, eventId: "   ", at: new Date(), action: "changed" },
      { _id: "bad-session", sessionId: "other-session", eventId: "bad-session", at: new Date(), action: "changed" },
    ]);

    const page = await getSessionCwdHistory(SESSION_ID, null);
    expect(page).toEqual({ items: [], nextCursor: null, totalItems: 0, totalSuccessfulItems: 0, complete: true });
    expect(aggregateCommands).toHaveLength(1);
    expect(aggregateCommands[0]?.pipeline).toEqual(buildSessionCwdHistoryPipeline(SESSION_ID, null, PAGE_SIZE));
  });
});
