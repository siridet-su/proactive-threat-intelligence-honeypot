import { Long } from "mongodb";
import { describe, expect, it } from "vitest";

import type { SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import {
  asSequence,
  buildSessionCwdHistoryQuery,
  decodeHistoryCursor,
  encodeHistoryCursor,
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
