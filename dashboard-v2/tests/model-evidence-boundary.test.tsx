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
  it("explains why classified-event and trusted-technique counts can differ", () => {
    const html = renderToStaticMarkup(createElement(ClassificationList, {
      items: [
        { evidence_id: "e1", technique_id: "T1033", event_id: "event-1" },
        { evidence_id: "e2", technique_id: "T1033", event_id: "event-2" },
        { evidence_id: "e3", technique_id: "T1105", event_id: "event-3" },
      ],
      trustedMappings: [
        { technique_id: "T1033", evidence_refs: [{ event_id: "event-1" }] },
        { technique_id: "T1105", evidence_refs: [{ event_id: "event-3" }] },
      ],
    }));
    expect(html).toContain("Trusted TTPs");
    expect(html).toContain("Classified events");
    expect(html).toContain("Counts describe different things");
    expect(html).toContain("does not automatically become a trusted mapping");
  });

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

    expect(html).toContain("Model1 advisory: T1105");
    expect(html).toContain("T1105");
    expect(html).not.toContain("LEGACY_SHADOW_SENTINEL");
    expect(html).not.toContain("Model2 shadow");
    expect(html).not.toContain("MODEL2_UNAVAILABLE");
  });

  it("keeps command-classification technical evidence inside one collapsed disclosure", () => {
    const html = renderToStaticMarkup(createElement(ClassificationList, {
      items: [{
        evidence_id: "classification-1",
        technique_id: "T1105",
        s1_advisory: { predicted_technique: "T1105" },
        traceability: { event_id: "event-1", model_source: "Model1" },
        authority_decision: { decision: "advisory" },
      }],
      trustedMappings: [],
    }));

    expect(html).toContain("Command classification details");
    expect(html).toContain("Evidence trace · technical details");
    expect(html.match(/<details/g)).toHaveLength(1);
    expect(html).not.toMatch(/<details[^>]*open(?:=|\s|>)/);
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

  it("requires an exact-session run binding before treating Model2 as available", () => {
    const sessionId = "session_v1_bound";
    expect(hasBoundAvailableModel2({
      session_id: sessionId,
      ensemble_evidence: {
        run_id: "run-1",
        model2: {
          available: true,
          status: "VALID_SHADOW",
          measurement_id: "measurement-1",
          episode_id: "episode-1",
          artifact_sha256: "artifact-hash",
          feature_contract_sha256: "contract-hash",
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
    expect(html).toContain("Observed behavior &amp; ATT&amp;CK mapping");
    expect(html).toContain("MITRE ATT&amp;CK");
    expect(html).toContain("T1033");
    expect(html).not.toContain("No classification evidence is available");
  });
});
