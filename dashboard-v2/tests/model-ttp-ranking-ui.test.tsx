import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Model2EnsembleSummary } from "../src/components/threat/SessionAnalysisPanels";

describe("Model1 + Model2 advisory panel", () => {
  it("explains the RRF formula without claiming confidence", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-a",
      session_ttp_advisory: {
        schema_version: "session_model1_ttp_advisory.v1", session_id: "session-a", authority: "ADVISORY_ONLY",
        assessed_command_events: 5,
        techniques: [
          { technique_id: "T1105", supporting_command_events: 3, evidence_refs: [{ command_ref: "index:0" }] },
          { technique_id: "T1110", supporting_command_events: 2, evidence_refs: [{ command_ref: "index:1" }] },
        ],
        rrf_recommendation: {
          schema_version: "session_ttp_rrf_advisory.v1", session_id: "session-a",
          method: "evidence_gated_reciprocal_rank_fusion", candidate_set_source: "MODEL1_ONLY",
          score_semantics: "RRF_RANK_SCORE_NOT_PROBABILITY_OR_CONFIDENCE", status: "MODEL1_ONLY",
          recommendation_order: ["T1105", "T1110"],
          rows: [
            { technique_id: "T1105", baseline_rank: 1, rrf_score: 0.016393, model2_rrf_component: 0, model2_support_added: false, eligible: false, exclusion_reason: "model2_unavailable" },
            { technique_id: "T1110", baseline_rank: 2, rrf_score: 0.016129, model2_rrf_component: 0, model2_support_added: false, eligible: false, exclusion_reason: "model2_unavailable" },
          ],
        },
      },
      ensemble_evidence: {
        run_id: "run-a", model1: { applicable: true },
        model2: { available: false, status: "INCONCLUSIVE_EXPERIMENTAL_SHADOW" },
        results: [],
      },
    }} />);
    expect(html).toContain("3 of 5 assessed command events");
    expect(html).toContain("Command refs: index:0");
    expect(html).toContain("Model1 only");
    expect(html).toContain("RRF rank score");
    expect(html).toContain("Gated weighted reciprocal-rank");
    expect(html).not.toContain("priority score");
    expect(html).not.toContain("Confidence: ");
  });
});
