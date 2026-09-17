import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ClassificationList,
  Model2EnsembleSummary,
} from "../src/components/threat/SessionAnalysisPanels";

describe("retired command shadow versus session-bound Model2", () => {
  it("does not mislabel a legacy command shadow as Model2 evidence", () => {
    const html = renderToStaticMarkup(createElement(ClassificationList, {
      items: [{
        evidence_id: "classification-1",
        technique_id: "T1105",
        s1_advisory: { predicted_technique: "T1105", decision_score: 0.72 },
        shadow_model: { technique_id: "LEGACY_SHADOW_SENTINEL", status: "unavailable" },
        authority_decision: { decision: "advisory" },
      }],
      trustedMappings: [],
    }));

    expect(html).toContain("Model1 advisory");
    expect(html).toContain("T1105");
    expect(html).not.toContain("LEGACY_SHADOW_SENTINEL");
    expect(html).not.toContain("Model2 shadow");
    expect(html).not.toContain("MODEL2_UNAVAILABLE");
  });

  it("renders Model2 only from the exact-session ensemble projection", () => {
    const html = renderToStaticMarkup(createElement(Model2EnsembleSummary, {
      data: {
        ensemble_evidence: {
          ensemble_authority: "ADVISORY_ONLY",
          model1: { applicable: true },
          model2: {
            available: true,
            status: "VALID_SHADOW",
            one_model: true,
            one_inference_call: true,
            independent_binary_heads: false,
          },
          results: [{
            technique_id: "T1105",
            evidence_state: "CORROBORATED",
            model1_result: "PRESENT",
            model2_result: "PRESENT",
          }],
        },
      },
    }));

    expect(html).toContain("VALID_SHADOW");
    expect(html).toContain("UNIFIED_ONE_MODEL");
    expect(html).toContain("CORROBORATED");
    expect(html).toContain("ADVISORY_ONLY");
  });
});
