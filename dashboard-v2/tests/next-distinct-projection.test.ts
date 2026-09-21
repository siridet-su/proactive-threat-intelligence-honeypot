import { describe, expect, it } from "vitest";

import {
  hasValidHistoricalNextDistinct,
  projectNextDistinct,
} from "@/lib/next-distinct-projection";

const endedFinalResult = {
  session_id: "session_v1_0123456789abcdef0123456789abcdef",
  state: "SESSION_ENDED",
  prediction_status: "PREDICTED",
  top1: "execution",
  stored_next_distinct_tactic: "execution",
  freshness: {
    state: "FINAL",
    session_ended: true,
    history_manifest_match: true,
  },
};

describe("Next-Distinct final historical projection", () => {
  it("retains a final manifest-bound result as historical context for an ended session", () => {
    expect(hasValidHistoricalNextDistinct(endedFinalResult, endedFinalResult.session_id)).toBe(true);

    const projected = projectNextDistinct(endedFinalResult, endedFinalResult.session_id);
    expect(projected.state).toBe("SESSION_ENDED");
    expect(projected.next_distinct_tactic).toBeNull();
    expect(projected.stored_next_distinct_tactic).toBe("execution");
    expect(projected.prediction_status_reason).toContain("historical advisory");
  });

  it("does not accept FINAL freshness unless it is explicitly bound to an ended session", () => {
    const unbound = {
      ...endedFinalResult,
      freshness: { ...endedFinalResult.freshness, session_ended: false },
    };
    expect(hasValidHistoricalNextDistinct(unbound, endedFinalResult.session_id)).toBe(false);
    expect(projectNextDistinct(unbound, endedFinalResult.session_id).stored_next_distinct_tactic).toBeNull();
  });

  it("fails closed on a history-manifest mismatch", () => {
    const mismatched = {
      ...endedFinalResult,
      freshness: { ...endedFinalResult.freshness, history_manifest_match: false },
    };
    expect(hasValidHistoricalNextDistinct(mismatched, endedFinalResult.session_id)).toBe(false);
    expect(projectNextDistinct(mismatched, endedFinalResult.session_id).stored_next_distinct_tactic).toBeNull();
  });

  it("keeps an active FRESH result in the current prediction field", () => {
    const active = {
      ...endedFinalResult,
      state: "DATA",
      session_ended: false,
      freshness: { state: "FRESH", history_manifest_match: true },
    };
    const projected = projectNextDistinct(active, endedFinalResult.session_id);
    expect(projected.state).toBe("DATA");
    expect(projected.next_distinct_tactic).toBe("execution");
    expect(projected.stored_next_distinct_tactic).toBeNull();
  });

  it("rejects a valid-looking result bound to another session", () => {
    const otherSession = {
      ...endedFinalResult,
      session_id: "session_v1_ffffffffffffffffffffffffffffffff",
    };
    expect(hasValidHistoricalNextDistinct(otherSession, endedFinalResult.session_id)).toBe(false);
    expect(projectNextDistinct(otherSession, endedFinalResult.session_id)).toMatchObject({
      state: "UNAVAILABLE",
      next_distinct_tactic: null,
      stored_next_distinct_tactic: null,
      session_id: endedFinalResult.session_id,
    });
  });

  it("requires FINAL rather than current freshness for a closed historical session", () => {
    const incorrectlyFresh = {
      ...endedFinalResult,
      freshness: { ...endedFinalResult.freshness, state: "FRESH" },
    };
    expect(hasValidHistoricalNextDistinct(incorrectlyFresh, endedFinalResult.session_id)).toBe(false);
    expect(projectNextDistinct(incorrectlyFresh, endedFinalResult.session_id).stored_next_distinct_tactic).toBeNull();
  });
});
