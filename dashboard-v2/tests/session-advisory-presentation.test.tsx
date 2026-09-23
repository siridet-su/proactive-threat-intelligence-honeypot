import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AiAdvisorySummary, Model2EnsembleSummary } from "../src/components/threat/SessionAnalysisPanels";

describe("session assessment presentation", () => {
  it("shows the actual AI-selected response finding and manual action, not just the provider", () => {
    const html = renderToStaticMarkup(<AiAdvisorySummary
      data={{
        status: "accepted",
        advisory: {
          rendered_advisory: { paragraphs: [{
            text: "AI selected 1 existing canonical finding family",
            finding_ids: ["response-guidance-1"],
            action_ids: ["review-auth-logs"],
          }] },
        },
      }}
      guidanceData={{ response_guidance: {
        findings: [{ finding_id: "response-guidance-1", statement: "Observed SSH interaction" }],
        advisory_actions: [{ action_id: "review-auth-logs", description: "Check authorised authentication logs" }],
      } }}
    />);
    expect(html).toContain("Observed SSH interaction");
    expect(html).toContain("Check authorised authentication logs");
    expect(html).toContain("the linked evidence is a response-guidance finding");
    expect(html).toContain("Existing manual action");
  });

  it("shows validated AI selections even when no narrative template was rendered", () => {
    const html = renderToStaticMarkup(<AiAdvisorySummary
      data={{ status: "accepted", advisory: {
        validated_advisory: {
          selected_finding_ids: ["finding-1"],
          selected_relationship_ids: ["relationship-1"],
          ranked_action_ids: ["action-1"],
        },
        rendered_advisory: { status: "rendered", paragraphs: [] },
      } }}
      guidanceData={{ response_guidance: {
        findings: [{ finding_id: "finding-1", statement: "Observed Cowrie interaction" }],
        advisory_actions: [{ action_id: "action-1", description: "Review authentication logs" }],
      } }}
    />);
    expect(html).toContain("AI selected 1 existing evidence item and 1 existing manual action");
    expect(html).toContain("Observed Cowrie interaction");
    expect(html).toContain("Review authentication logs");
    expect(html).toContain("no rendered narrative was recorded");
  });

  it("does not imply that an unavailable Model2 corroborated the session", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-v1",
      ensemble_evidence: { model1: { applicable: true }, model2: { available: false, status: "INCONCLUSIVE_EXPERIMENTAL_SHADOW" } },
    }} />);
    expect(html).toContain("No session-bound Model2 result is available");
    expect(html).toContain("no ensemble corroboration or combined score is claimed");
  });
});
