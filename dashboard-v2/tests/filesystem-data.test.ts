import { Long } from "mongodb";
import { describe, expect, it } from "vitest";

import type { SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import {
  asSequence,
  buildAuditSessionsQuery,
  buildSessionCwdHistoryQuery,
  decodeAuditSessionCursor,
  decodeHistoryCursor,
  encodeAuditSessionCursor,
  encodeHistoryCursor,
  normalizeSessionAuditSummary,
  normalizeHistoryEvent,
} from "../src/lib/filesystem-data";

const at = "2026-09-09T00:00:00.123Z";

function historyEvent(overrides: Partial<SessionCwdHistoryEvent> = {}): SessionCwdHistoryEvent {
  return {
    id: "cwd:event-b",
    sessionId: "session-1",
    sequence: "1788912000123000000",
    at,
    fromPath: "/home/operator",
    toPath: "/var/tmp",
    action: "changed",
    status: "confirmed",
    sourceEventId: "event-b",
    ...overrides,
  };
}

describe("filesystem history cursor", () => {
  it("round-trips both timestamp and event-id sort keys", () => {
    const cursor = encodeHistoryCursor(historyEvent());
    expect(decodeHistoryCursor(cursor)).toEqual({ at, id: "cwd:event-b" });
  });

  it("keeps events with the cursor timestamp and a lower event id", () => {
    const cursor = encodeHistoryCursor(historyEvent());
    const query = buildSessionCwdHistoryQuery("session-1", cursor);

    expect(query).toEqual({
      $and: [
        { $or: [{ sessionId: "session-1" }, { session_id: "session-1" }] },
        {
          $or: [
            { at: { $lt: new Date(at) } },
            { at: new Date(at), eventId: { $lt: "cwd:event-b" } },
          ],
        },
      ],
    });
  });

  it("ignores malformed cursors without broadening the session scope", () => {
    expect(buildSessionCwdHistoryQuery("session-1", "not-base64-json")).toEqual({
      $or: [{ sessionId: "session-1" }, { session_id: "session-1" }],
    });
  });
});

describe("filesystem session audit summary", () => {
  it("uses complete visited paths to classify a session that left home", () => {
    expect(normalizeSessionAuditSummary(
      "/home/operator",
      ["/home/operator", "/"],
      ["/etc", "/home/operator"],
      3,
    )).toEqual({
      visitedPaths: ["/", "/etc", "/home/operator"],
      homeOnly: false,
      eventCount: 3,
    });
  });

  it("allows root traversal but requires at least one observed home path", () => {
    expect(normalizeSessionAuditSummary("/", ["/home/operator"], ["/"], 2).homeOnly).toBe(true);
    expect(normalizeSessionAuditSummary("/", ["/"], [null], 1).homeOnly).toBe(false);
  });

  it("drops unknown and relative path values from filter evidence", () => {
    expect(normalizeSessionAuditSummary("/home/operator", ["unknown", "tmp"], [null, 7], -1)).toEqual({
      visitedPaths: ["/home/operator"],
      homeOnly: true,
      eventCount: 0,
    });
  });
});

describe("filesystem sequence normalization", () => {
  it("preserves BSON Int64 values as lossless decimal strings", () => {
    const sequence = Long.fromString("1788912000123000000");
    expect(asSequence(sequence)).toBe("1788912000123000000");
    expect(normalizeHistoryEvent({
      _id: "cwd:event-b",
      eventId: "cwd:event-b",
      sessionId: "session-1",
      sequence,
      at: new Date(at),
      action: "changed",
      status: "confirmed",
    })?.sequence).toBe("1788912000123000000");
  });

  it("rejects unsafe JavaScript numbers instead of rounding them", () => {
    expect(asSequence(1_788_912_000_123_000_000)).toBeNull();
  });
});

describe("filesystem audit sessions cursor and query", () => {
  const closedAt = "2026-09-10T12:00:00.000Z";
  const sessionId = "session-closed-xyz";

  it("round-trips closedAt and sessionId sort keys", () => {
    const cursor = encodeAuditSessionCursor(closedAt, sessionId);
    expect(decodeAuditSessionCursor(cursor)).toEqual({ closedAt, sessionId });
  });

  it("handles null or invalid cursor gracefully", () => {
    expect(decodeAuditSessionCursor(null)).toBeNull();
    expect(decodeAuditSessionCursor("invalid-base64")).toBeNull();
    expect(decodeAuditSessionCursor(Buffer.from("{\"foo\":\"bar\"}").toString("base64url"))).toBeNull();
  });

  it("builds closed directory query without search or cursor", () => {
    const query = buildAuditSessionsQuery({});
    expect(query).toEqual({
      $and: [
        { "lifecycle.status": "closed" },
        { "cwdState.path": { $type: "string", $ne: "" } },
      ],
    });
  });

  it("escapes special characters in regex search across session, IP, and path", () => {
    const query = buildAuditSessionsQuery({ search: "192.168.1.1 (test)" });
    expect(query).toEqual({
      $and: [
        { "lifecycle.status": "closed" },
        { "cwdState.path": { $type: "string", $ne: "" } },
        {
          $or: [
            { sessionId: { $regex: /192\.168\.1\.1 \(test\)/i } },
            { sourceIp: { $regex: /192\.168\.1\.1 \(test\)/i } },
            { "cwdState.path": { $regex: /192\.168\.1\.1 \(test\)/i } },
          ],
        },
      ],
    });
  });

  it("applies keyset pagination condition from cursor", () => {
    const cursor = encodeAuditSessionCursor(closedAt, sessionId);
    const query = buildAuditSessionsQuery({ cursor });
    expect(query).toEqual({
      $and: [
        { "lifecycle.status": "closed" },
        { "cwdState.path": { $type: "string", $ne: "" } },
        {
          $or: [
            { "lifecycle.closedAt": { $lt: closedAt } },
            { "lifecycle.closedAt": closedAt, sessionId: { $lt: sessionId } },
          ],
        },
      ],
    });
  });
});
