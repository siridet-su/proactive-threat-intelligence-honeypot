import { describe, expect, it } from "vitest";

import { projectContextualHypotheses } from "@/lib/contextual-hypothesis-presentation";

describe("contextual hypothesis presentation", () => {
  it("projects useful non-authoritative correlation details without raw evidence text", () => {
    const rows = projectContextualHypotheses([{
      correlation_id: "corr-1",
      main_ttp: "T1059",
      predicted_technique: {
        main_ttp: "T1059",
        technique_name: "Command and Scripting Interpreter",
        tactic: "execution",
      },
      rule_id: "cowrie-shell-sequence",
      source_type: "cowrie_session",
      claim_status: "CONTEXTUAL_ONLY",
      matched_conditions: [{
        condition: { type: "event_sequence" },
        description: "A policy-defined event sequence was observed.",
        evidence: [{ command: "echo username:attacker-password" }],
      }],
      evidence: ["echo username:attacker-password"],
      reason: "echo username:attacker-password",
    }]);

    expect(rows).toEqual([{
      key: "corr-1",
      techniqueId: "T1059",
      techniqueName: "Command and Scripting Interpreter",
      tactic: "execution",
      ruleId: "cowrie-shell-sequence",
      sourceType: "cowrie_session",
      claimStatus: "CONTEXTUAL_ONLY",
      matchedConditions: [{ type: "event_sequence", description: "A policy-defined event sequence was observed." }],
    }]);
    expect(JSON.stringify(rows)).not.toContain("attacker-password");
  });

  it("bounds untrusted arrays and text and ignores malformed rows", () => {
    const rows = projectContextualHypotheses([
      null,
      ...Array.from({ length: 12 }, (_, index) => ({
        correlation_id: `corr-${index}`,
        rule_id: "r".repeat(200),
        matched_conditions: Array.from({ length: 10 }, () => ({
          condition: { type: "x".repeat(100) },
          description: "d".repeat(300),
        })),
      })),
    ]);

    expect(rows).toHaveLength(10);
    expect(rows[0].ruleId).toHaveLength(128);
    expect(rows[0].matchedConditions).toHaveLength(4);
    expect(rows[0].matchedConditions[0].type).toHaveLength(64);
    expect(rows[0].matchedConditions[0].description).toHaveLength(240);
  });
});
