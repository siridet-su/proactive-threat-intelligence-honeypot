import { describe, expect, it } from "vitest";
import { hasBoundModel2, rankTtpRecommendations } from "../src/lib/model-ttp-ranking";

const sessionId = "session-v1";

function fixture() {
  return {
    session_id: sessionId,
    session_ttp_advisory: {
      schema_version: "session_model1_ttp_advisory.v1",
      session_id: sessionId,
      authority: "ADVISORY_ONLY",
      assessed_command_events: 5,
      techniques: [
        { technique_id: "T1105", supporting_command_events: 3, evidence_refs: [{ command_ref: "index:0", evidence_id: "a" }] },
        { technique_id: "T1110", supporting_command_events: 2, evidence_refs: [{ command_ref: "index:1", evidence_id: "b" }] },
      ],
      rrf_recommendation: {
        schema_version: "session_ttp_rrf_advisory.v1", session_id: sessionId,
        method: "evidence_gated_reciprocal_rank_fusion", candidate_set_source: "MODEL1_ONLY",
        score_semantics: "RRF_RANK_SCORE_NOT_PROBABILITY_OR_CONFIDENCE",
        recommendation_order: ["T1110", "T1105"],
        rows: [
          { technique_id: "T1110", baseline_rank: 2, rrf_score: 0.0202, model2_rrf_component: 0.0041, model2_support_added: true, eligible: true, model2_decision: "PRESENT", exclusion_reason: null },
          { technique_id: "T1105", baseline_rank: 1, rrf_score: 0.0164, model2_rrf_component: 0, model2_support_added: false, eligible: true, model2_decision: "ABSENT", exclusion_reason: null },
        ],
      },
    },
    ensemble_evidence: {
      run_id: "run-1",
      model2: {
        available: true, status: "VALID_SHADOW", artifact_sha256: "artifact-hash",
        feature_contract_sha256: "features-hash", measurement_id: "measurement-1", episode_id: "episode-1",
        binding: { session_id: sessionId, run_id: "run-1", measurement_id: "measurement-1", episode_id: "episode-1" },
      },
      results: [
        { technique_id: "T1105", model2_available: true, model2_result: "ABSENT" },
        { technique_id: "T1110", model2_available: true, model2_result: "PRESENT" },
      ],
    },
  };
}

describe("session-level Model1 advisory", () => {
  it("uses the server-owned RRF order without ranking by raw model scores", () => {
    const ranked = rankTtpRecommendations(fixture());
    expect(ranked.map((item) => item.techniqueId)).toEqual(["T1110", "T1105"]);
    expect(ranked.map((item) => item.supportingCommandEvents)).toEqual([2, 3]);
    expect(ranked.map((item) => item.model2Support)).toEqual(["corroborates", "does_not_support"]);
    expect(ranked[1].evidenceRefs[0].commandRef).toBe("index:0");
    expect(ranked[0].rrfScore).toBe(0.0202);
    expect(ranked[0]).not.toHaveProperty("score");
  });

  it("does not treat cross-session or unavailable Model2 as corroboration", () => {
    const value = fixture();
    value.ensemble_evidence.model2.binding.session_id = "other";
    expect(hasBoundModel2(value)).toBe(false);
    // The UI consumes the already-gated server projection; it does not
    // reconstruct or override RRF from raw Model2 evidence.
    expect(rankTtpRecommendations(value)[0].model2SupportAdded).toBe(true);
  });

  it("fails closed on missing or cross-session advisory, and invalid counts", () => {
    const value = fixture();
    value.session_ttp_advisory.session_id = "other";
    expect(rankTtpRecommendations(value)).toEqual([]);
    value.session_ttp_advisory.session_id = sessionId;
    value.session_ttp_advisory.techniques[0].supporting_command_events = 6;
    expect(rankTtpRecommendations(value).map((item) => item.techniqueId)).toEqual(["T1110"]);
  });
});
