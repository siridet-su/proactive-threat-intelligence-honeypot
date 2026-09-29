import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AiAdvisorySummary, ExternalTiSummary, HypothesisSummary, Model2EnsembleSummary, ProvenanceSummary, shouldPollExternalTi } from "../src/components/threat/SessionAnalysisPanels";

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

  it("labels disabled provider records as evidence records rather than findings", () => {
    const html = renderToStaticMarkup(<ExternalTiSummary
      sessionData={{
        status: "TI_PENDING",
        status_reason: "POLICY_BLOCKED",
        status_reason_text: "Provider lookup blocked by policy.",
        enrichment_job_summary: { pending: false },
        evidence: [{ provider: "virustotal", lookup_status: "DISABLED", finding_state: "PENDING" }],
      }}
      observableData={{}}
    />);
    expect(html).toContain("1 provider evidence record");
    expect(html).toContain("0 usable provider results");
    expect(html).toContain("Provider evidence records");
    expect(html).toContain("Provider lookup blocked by policy.");
    expect(html).not.toContain("Linked findings");
    expect(html).not.toContain("separately linked finding");
  });

  it("polls external TI only while a provider-result job is genuinely pending", () => {
    expect(shouldPollExternalTi({
      status: "TI_PENDING",
      status_reason: "PROVIDER_RESULT_PENDING",
      enrichment_job_summary: { pending: true },
    })).toBe(true);
    expect(shouldPollExternalTi({
      status: "TI_PENDING",
      status_reason: "POLICY_BLOCKED",
      enrichment_job_summary: { pending: false },
    })).toBe(false);
    expect(shouldPollExternalTi({
      status: "TI_PENDING",
      status_reason: "PROVIDER_RESULT_PENDING",
      enrichment_job_summary: { pending: false },
    })).toBe(false);
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
    expect(html).toContain("its selected ID belongs to response guidance");
    expect(html).toContain("Existing action selected for review");
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

  it("explains an accepted AI abstention without claiming selected data", () => {
    const html = renderToStaticMarkup(<AiAdvisorySummary
      data={{ status: "accepted", advisory: {
        validated_advisory: {
          abstained: true,
          selected_finding_ids: [],
          selected_relationship_ids: [],
          ranked_action_ids: [],
        },
        rendered_advisory: { status: "rendered", paragraphs: [] },
      } }}
      guidanceData={{ response_guidance: { findings: [], advisory_actions: [] } }}
    />);
    expect(html).toContain("accepted and validated, but it abstained");
    expect(html).not.toContain("AI selected 1");
  });

  it("does not imply that an unavailable Model2 corroborated the session", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-v1",
      ensemble_evidence: { model1: { applicable: true }, model2: { available: false, status: "INCONCLUSIVE_EXPERIMENTAL_SHADOW" } },
    }} />);
    expect(html).toContain("No session-bound Model2 result is available");
    expect(html).toContain("no ensemble corroboration or combined score is claimed");
  });

  it("labels Model2-only predictions as experimental and explains unbound T1046 context", () => {
    const sessionId = "session_v1_model2_boundary";
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: sessionId,
      ensemble_evidence: {
        session_id: sessionId, run_id: "run-1",
        model1: { applicable: false },
        model2: {
          available: true, availability: "PARTIAL", status: "VALID_SHADOW",
          measurement_id: "measurement-1", episode_id: "episode-1",
          artifact_sha256: "a".repeat(64), feature_contract_sha256: "b".repeat(64),
          binding: { session_id: sessionId, run_id: "run-1", measurement_id: "measurement-1", episode_id: "episode-1" },
          unavailable_heads: { T1046: "t1046_unbound_sensor_context" },
        },
        results: [{ technique_id: "T1110", model2_result: "PRESENT", model2_relation: "MODEL2_ONLY" }],
      },
    }} />);
    expect(html).toContain("Experimental Model2-only prediction for T1110");
    expect(html).toContain("not a confirmed observed behavior, canonical finding");
    expect(html).toContain("not bound to this Cowrie session");
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

  it("shows outcomes from each active behavior family without creating extra hypotheses", () => {
    const html = renderToStaticMarkup(<HypothesisSummary data={{
      hypothesis_sets: [{ question: "What explains the credential-related path access attempt?", hypotheses: [] }],
      correlated_ttp_hypotheses: [],
      session_hypothesis_assessment: { semantic_families: [
        { semantic_family: "transfer", status: "canonical_finding", observed_fact_count: 1, trusted_finding_ids: ["finding-transfer"] },
        { semantic_family: "filesystem", status: "canonical_finding", observed_fact_count: 1, trusted_finding_ids: ["finding-file"] },
        { semantic_family: "sensitive_read", status: "insufficient_evidence", observed_fact_count: 1, missing_evidence: ["outcome_not_eligible"] },
        { semantic_family: "execution", status: "not_observed", observed_fact_count: 0 },
      ] },
    }} />);
    expect(html).toContain("Behavior family results");
    expect(html).toContain("File transfer");
    expect(html).toContain("File changes");
    expect(html).toContain("Credential-related read");
    expect(html).toContain("Evidence incomplete");
    expect(html).toContain("1 evidence-bounded hypothesis set recorded");
    expect(html).toContain("1 other behavior check");
  });

  it("renders more than ten bounded hypothesis sets without silently truncating them", () => {
    const html = renderToStaticMarkup(<HypothesisSummary data={{
      hypothesis_sets: Array.from({ length: 13 }, (_, index) => ({
        hypothesis_set_id: `set-${index}`,
        question: `Bounded question ${index}`,
        hypotheses: [{ hypothesis_id: `hypothesis-${index}`, statement: `Bounded statement ${index}` }],
      })),
      correlated_ttp_hypotheses: [],
    }} />);
    expect(html).toContain("13 evidence-bounded hypothesis sets recorded");
    expect(html).toContain("Bounded question 12");
    expect(html).toContain("Bounded statement 12");
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
