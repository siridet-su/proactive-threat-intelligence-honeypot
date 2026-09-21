import assert from "node:assert/strict";
import test from "node:test";

import {
  externalTiFreshness,
  latestExternalTiRetrievalAt,
  sourceIpCacheFreshness,
} from "../src/lib/external-ti-presentation.ts";

const asOf = "2026-09-20T06:00:00.000Z";

test("shows mixed freshness when fresh source-IP cache coexists with stale legacy evidence", () => {
  const result = externalTiFreshness({
    rawState: "TI_EXPIRED",
    freshness: { state: "TI_EXPIRED", latest_retrieved_at: "2026-09-05T05:03:51.000Z" },
    evidence: [{ provider: "otx", freshness_state: "STALE", retrieved_at: "2026-09-05T05:03:51.000Z" }],
    cache: [{ provider: "otx", lookup_status: "OK", lookup_at: "2026-09-20T05:03:51.000Z", expires_at: "2026-09-21T05:03:51.000Z" }],
    asOf,
  });

  assert.equal(result.state, "MIXED");
  assert.equal(result.freshCacheCount, 1);
  assert.equal(result.staleEvidenceCount, 1);
});

test("uses the newest cache lookup for the aggregate retrieval timestamp", () => {
  assert.equal(latestExternalTiRetrievalAt({
    freshness: { latest_retrieved_at: "2026-09-05T05:03:51.000Z" },
    summary: { source_ip_cache_latest_lookup_at: "2026-09-20T05:03:51.045Z" },
    cache: [{ lookup_at: "2026-09-20T05:03:50.900Z" }],
  }), "2026-09-20T05:03:51.045Z");
});

test("marks a cache result stale after its expiry time", () => {
  assert.equal(sourceIpCacheFreshness({
    lookup_status: "OK",
    lookup_at: "2026-09-19T05:03:51.000Z",
    expires_at: "2026-09-20T05:03:51.000Z",
}, asOf), "STALE");
});

test("expiry overrides a contradictory fresh marker", () => {
  assert.equal(sourceIpCacheFreshness({
    lookup_status: "OK",
    freshness_state: "FRESH",
    expires_at: "2026-09-20T05:03:51.000Z",
  }, asOf), "STALE");
});

test("preserves the API freshness state when no newer source-IP cache data exists", () => {
  const result = externalTiFreshness({
    rawState: "TI_EXPIRED",
    evidence: [{ freshness_state: "STALE", retrieved_at: "2026-09-05T05:03:51.000Z" }],
    cache: [],
    asOf,
  });

  assert.equal(result.state, "TI_EXPIRED");
  assert.equal(result.freshCacheCount, 0);
});

test("does not call an incomplete cache record fresh", () => {
  assert.equal(sourceIpCacheFreshness({ lookup_status: "OK", lookup_at: "2026-09-20T05:03:51.000Z" }, asOf), "NOT_RECORDED");
});

test("keeps freshness unknown until the client clock has been observed", () => {
  const result = externalTiFreshness({
    rawState: "TI_EXPIRED",
    cache: [{ lookup_status: "OK", expires_at: "2026-09-21T05:03:51.000Z" }],
    asOf: null,
  });

  assert.equal(result.state, "TI_EXPIRED");
  assert.equal(result.freshCacheCount, 0);
});
