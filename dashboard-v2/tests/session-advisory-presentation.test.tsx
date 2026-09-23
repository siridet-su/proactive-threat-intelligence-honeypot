import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AiAdvisorySummary, ExternalTiSummary, HypothesisSummary, Model2EnsembleSummary, ProvenanceSummary } from "../src/components/threat/SessionAnalysisPanels";

describe("session assessment presentation", () => {
  it("shows normalized public-source provider results, including nested OTX pulses, without double-counting cache", () => {
    const sourceIpCache = [
      { provider: "abuseipdb", cache_key: "abuse-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { abuse_confidence_score: 100, total_reports: 1809, country_code: "SE" } },
      { provider: "otx", cache_key: "otx-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { pulses: [{ pulse_id: "p1", name: "Observed SSH scanner feed" }], truncated: false } },
      { provider: "shodan_official", cache_key: "shodan-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { ports: [22, 80], service_product_summary: ["ssh 22", "nginx 80"] } },
    ];
    const html = renderToStaticMarkup(<ExternalTiSummary
      sessionData={{ status: "TI_AVAILABLE", counts: { eligible_observables: 1 }, source_ip_cache: sourceIpCache }}
      observableData={{ source_ip_cache: sourceIpCache, observable: { value: "203.0.113.9" } }}
    />);
    expect(html).toContain("AbuseIPDB score:");
    expect(html).toContain("1809 community reports");
    expect(html).toContain("OTX pulse matches: 1");
    expect(html).toContain("Observed SSH scanner feed");
    expect(html).toContain("ssh 22");
    expect(html).toContain("3 source-IP provider lookup results");
    expect(html).toContain("What the providers reported");
    expect(html).toContain("Lookup provenance and technical details");
    expect(html).not.toContain("abuseipdb cache");
    expect(html).not.toContain("normalized context:");
    expect(html).not.toContain("6 source-IP provider lookup results");
  });

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

  it("explains why a session has no bounded hypothesis without promoting context", () => {
    const html = renderToStaticMarkup(<HypothesisSummary data={{
      hypothesis_sets: [], correlated_ttp_hypotheses: [],
      session_hypothesis_assessment: { missing_evidence: ["effect_status_not_eligible"],
        semantic_families: [{ semantic_family: "filesystem", status: "insufficient_evidence", observed_fact_count: 1, missing_evidence: ["effect_status_not_eligible"] }] },
    }} />);
    expect(html).toContain("Why no hypothesis was established");
    expect(html).toContain("did not confirm the required effect");
    expect(html).toContain("not proof that its effect succeeded");
  });

  it("explains exactly which Model2 head makes a bound result partial", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-1", ensemble_evidence: { session_id: "session-1", run_id: "run-1",
        model2: { available: true, availability: "PARTIAL", status: "VALID_SHADOW",
          measurement_id: "measurement-1", episode_id: "episode-1", artifact_sha256: "a".repeat(64), feature_contract_sha256: "b".repeat(64),
          binding: { session_id: "session-1", run_id: "run-1", measurement_id: "measurement-1", episode_id: "episode-1" },
          unavailable_heads: { T1046: "t1046_multiservice_scan_evidence_missing" } } },
    }} />);
    expect(html).toContain("Why Model2 is partial");
    expect(html).toContain("No exact-bound multiservice scan observation");
    expect(html).not.toContain("No session-bound Model2 result is available");
  });

  it("separates the immutable assessment AI flag from current accepted advisory", () => {
    const html = renderToStaticMarkup(<ProvenanceSummary value={{ report_summary: {
      ai_enriched: "false", current_ai_advisory_status: "accepted",
    } }} />);
    expect(html).toContain("immutable assessment was generated without AI enrichment");
    expect(html).toContain("Current AI advisory");
    expect(html).toContain("accepted");
  });
});
