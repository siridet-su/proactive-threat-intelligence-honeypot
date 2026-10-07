import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDeceptionSessionQuery,
  matchesDeceptionSessionBinding,
} from "../src/lib/deception-binding.ts";

const sessionId = "session_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const decision = { ip: "192.0.2.10", session_id: sessionId };

test("session-detail query requires both exact bindings", () => {
  assert.deepEqual(buildDeceptionSessionQuery(" 192.0.2.10 ", sessionId), {
    ip: "192.0.2.10",
    session_id: sessionId,
  });
  assert.equal(buildDeceptionSessionQuery("192.0.2.10", " "), null);
  assert.equal(buildDeceptionSessionQuery(" ", sessionId), null);
});

test("rejects deception records bound to another session or origin", () => {
  assert.equal(matchesDeceptionSessionBinding(decision, decision.ip, sessionId), true);
  assert.equal(matchesDeceptionSessionBinding(decision, decision.ip, "session_v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), false);
  assert.equal(matchesDeceptionSessionBinding(decision, "192.0.2.11", sessionId), false);
  assert.equal(matchesDeceptionSessionBinding([], decision.ip, sessionId), false);
  assert.equal(matchesDeceptionSessionBinding(decision, decision.ip, ""), false);
});
