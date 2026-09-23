import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ClassificationList,
  Model2EnsembleSummary,
  hasBoundAvailableModel2,
  hasClassificationEvidence,
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

    expect(html).toContain("Model1 is advisory");
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
    expect(html).toMatch(/corroborated/i);
    expect(html).toContain("ADVISORY_ONLY");
  });

  it("requires an exact-session run binding before treating Model2 as available", () => {
    const sessionId = "session_v1_bound";
    expect(hasBoundAvailableModel2({
      session_id: sessionId,
      ensemble_evidence: {
        run_id: "run-1",
        model2: {
          available: true,
          status: "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW",
          artifact_sha256: "artifact-hash",
          feature_contract_sha256: "feature-hash",
          measurement_id: "measurement-1",
          episode_id: "episode-1",
          binding: { session_id: sessionId, run_id: "run-1", measurement_id: "measurement-1", episode_id: "episode-1" },
        },
      },
    })).toBe(true);

    expect(hasBoundAvailableModel2({
      session_id: sessionId,
      ensemble_evidence: {
        model2: {
          available: false,
          status: "INCONCLUSIVE_EXPERIMENTAL_SHADOW",
          binding: {},
        },
      },
    })).toBe(false);

    expect(hasBoundAvailableModel2({
      session_id: sessionId,
      ensemble_evidence: {
        run_id: "run-other",
        model2: {
          available: true,
          binding: { session_id: "session_v1_other", run_id: "run-other" },
        },
      },
    })).toBe(false);
  });

  it("keeps trusted ATT&CK mappings visible when command classification rows are absent", () => {
    const trustedMapping = {
      technique_id: "T1033",
      tactics: ["discovery"],
      trust_tier: "trusted_observation",
      mapping_semantics: "trusted_command_event_observation",
    };
    const html = renderToStaticMarkup(createElement(ClassificationList, {
      items: [],
      trustedMappings: [trustedMapping],
    }));

    expect(hasClassificationEvidence([], [trustedMapping])).toBe(true);
    expect(hasClassificationEvidence([], [])).toBe(false);
    expect(html).toContain("Trusted ATT&amp;CK mapping details");
    expect(html).toContain("T1033");
    expect(html).not.toContain("No classification evidence is available");
  });
});
