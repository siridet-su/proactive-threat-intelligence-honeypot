import { describe, expect, it } from "vitest";

import { hasRankableModel2, rankTtpRecommendations } from "../src/lib/model-ttp-ranking";

const sessionId = "session-v1";

function fixture(model2Result: "PRESENT" | "ABSENT" | null = "PRESENT") {
  return {
    session_id: sessionId,
    ensemble_evidence: {
      run_id: "run-1",
      model1: { applicable: true },
      model2: {
        available: true,
        status: "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW",
        artifact_sha256: "artifact-hash",
        feature_contract_sha256: "features-hash",
        measurement_id: "measurement-1",
        episode_id: "episode-1",
        binding: {
          session_id: sessionId,
          run_id: "run-1",
          measurement_id: "measurement-1",
          episode_id: "episode-1",
        },
      },
      results: [
        { technique_id: "T1105", model1_result: "PRESENT", model1_margin: 3, model2_result: "ABSENT" },
        { technique_id: "T1110", model1_result: "PRESENT", model1_margin: 2, model2_result: model2Result },
        { technique_id: "T1046", model1_result: "PRESENT", model1_margin: 1, model2_result: null },
      ],
      model1_only_labels: [] as Array<Record<string, unknown>>,
    },
  };
}

describe("TTP rank-based advisory priority", () => {
  it("ranks A/B/C with joint support B first without claiming calibrated confidence", () => {
    const ranked = rankTtpRecommendations(fixture());
    expect(ranked.map((item) => item.techniqueId)).toEqual(["T1110", "T1105", "T1046"]);
    expect(ranked[0].score).toBeCloseTo(1 / 62 + 1 / 61);
    expect(ranked[0].model2Support).toBe("corroborates");
    expect(ranked[1].model2Support).toBe("contradicts");
    expect(ranked[2].model2Support).toBe("unavailable");
  });

  it("does not vote with an unavailable or cross-session Model2", () => {
    const unavailable = fixture();
    unavailable.ensemble_evidence.model2.available = false;
    expect(rankTtpRecommendations(unavailable).map((item) => item.techniqueId)).toEqual(["T1105", "T1110", "T1046"]);
    expect(rankTtpRecommendations(unavailable).every((item) => item.model2Support === "unavailable")).toBe(true);

    const wrongBinding = fixture();
    wrongBinding.ensemble_evidence.model2.binding.session_id = "another-session";
    expect(hasRankableModel2(wrongBinding)).toBe(false);
    expect(rankTtpRecommendations(wrongBinding)[0].techniqueId).toBe("T1105");
    const wrongRun = fixture();
    wrongRun.ensemble_evidence.model2.binding.run_id = "another-run";
    expect(hasRankableModel2(wrongRun)).toBe(false);
    const missingMeasurement = fixture();
    missingMeasurement.ensemble_evidence.model2.measurement_id = "";
    expect(hasRankableModel2(missingMeasurement)).toBe(false);
  });

  it("does not promote Model2-only or unavailable-head labels into primary recommendations", () => {
    const value = fixture(null);
    value.ensemble_evidence.results[0].model1_result = "ABSENT";
    value.ensemble_evidence.results[0].model2_result = "PRESENT";
    expect(rankTtpRecommendations(value).map((item) => item.techniqueId)).toEqual(["T1110", "T1046"]);
  });

  it("keeps Model1-only labels and does not use raw scores or missing margins as probabilities", () => {
    const value = fixture("ABSENT");
    value.ensemble_evidence.model1_only_labels = [{ technique_id: "T1033", result: "PRESENT", decision_score: 1.5 }];
    expect(rankTtpRecommendations(value).map((item) => item.techniqueId)).toEqual(["T1105", "T1110", "T1033", "T1046"]);
  });
});
