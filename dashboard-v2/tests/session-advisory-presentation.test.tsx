import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AiAdvisorySummary, ExternalTiSummary, HypothesisSummary, Model2EnsembleSummary, ProvenanceSummary, SourcePivotSummary, TimelineList } from "../src/components/threat/SessionAnalysisPanels";

describe("session assessment presentation", () => {
  it("renders a compact vertical event chain inside its own bounded scroll region", () => {
    const html = renderToStaticMarkup(<TimelineList items={[
      { eventid: "cowrie.session.connect", timestamp: "2026-09-27T08:00:00Z", sensor_id: "test-sensor", src_ip: "192.0.2.10" },
      { eventid: "cowrie.client.kex", timestamp: "2026-09-27T08:00:01Z", sensor_id: "test-sensor", src_ip: "192.0.2.10" },
      { eventid: "cowrie.session.closed", timestamp: "2026-09-27T08:00:02Z", sensor_id: "test-sensor", src_ip: "192.0.2.10" },
    ]} />);

    expect(html).toContain("Bound event chain");
    expect(html).toContain("h-[min(65vh,28rem)] overflow-y-auto");
    expect(html).toContain("grid-cols-[1rem_minmax(0,1fr)]");
    expect(html).toContain("grid-cols-[minmax(0,1fr)_9.5rem_3.5rem]");
    expect(html).toContain("sm:grid-cols-[minmax(0,1fr)_15rem_4rem]");
    expect(html.match(/data-testid="timeline-event-row"/g)).toHaveLength(3);
    expect(html.match(/data-testid="timeline-state-slot"/g)).toHaveLength(3);
    expect(html).toContain("-bottom-2.5 left-[0.4375rem] top-4 w-px bg-primary-navy-line");
    expect(html).toContain("bg-primary-navy-line");
    expect(html).toContain("LATEST");
    expect(html).not.toContain("overflow-x-auto");
  });

  it("keeps the newest bounded timeline window and marks its actual latest event", () => {
    const items = Array.from({ length: 101 }, (_, index) => ({
      eventid: "cowrie.session.connect",
      timestamp: new Date(Date.UTC(2026, 8, 27, 8, 0, index)).toISOString(),
      sensor_id: `event-${index}`,
    }));
    const html = renderToStaticMarkup(<TimelineList items={items} />);

    expect(html).not.toContain("event-0");
    expect(html).toContain("event-100");
    expect(html.match(/>LATEST<\/span>/g)).toHaveLength(1);
  });

  it("keeps technical model details collapsed and compacts mostly unavailable fields", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-technical-details",
      ensemble_evidence: { model1: { applicable: true } },
    }} />);

    expect(html).toContain("Technical details");
    expect(html).toContain("Limited technical detail · 1 of 11 fields recorded.");
    expect(html).not.toMatch(/<details[^>]*open(?:=|\s|>)/);
    expect(html.match(/<details/g)).toHaveLength(1);
  });

  it("shows up to 50 hypothesis sets and discloses when the display bound is exceeded", () => {
    const hypothesisSets = Array.from({ length: 55 }, (_, index) => ({
      hypothesis_set_id: `set-${index}`,
      question: `Question ${index}`,
      hypotheses: [{ hypothesis_id: `hypothesis-${index}`, statement: `Statement ${index}` }],
    }));
    const html = renderToStaticMarkup(<HypothesisSummary data={{ hypothesis_sets: hypothesisSets }} />);

    expect(html).toContain("Showing the first 50 of 55 hypothesis sets.");
    expect(html).toContain("Question 49");
    expect(html).not.toContain("Question 50");
  });

  it("discloses when the backend bounded projection omitted additional sets", () => {
    const hypothesisSets = Array.from({ length: 50 }, (_, index) => ({
      hypothesis_set_id: `set-${index}`,
      question: `Question ${index}`,
      hypotheses: [],
    }));
    const html = renderToStaticMarkup(<HypothesisSummary data={{
      hypothesis_sets: hypothesisSets,
      hypothesis_sets_truncated: true,
    }} />);

    expect(html).toContain("At least 50 evidence-bounded hypothesis sets recorded");
    expect(html).toContain("additional sets were omitted by the bounded monitor projection.");
  });

  it("keeps source-IP recurrence rows within a sticky-header scroll frame", () => {
    const sessions = Array.from({ length: 25 }, (_, index) => ({
      session_id: `session-${index + 1}`,
      first_seen: "2026-09-27T08:00:00Z",
      last_seen: "2026-09-27T08:01:00Z",
      sighting_count: index + 1,
    }));
    const html = renderToStaticMarkup(<SourcePivotSummary data={{
      observable: { value: "192.0.2.10" },
      counts: { sessions_found: sessions.length, sightings_examined: 325 },
      provider_calls: false,
      sessions,
    }} />);

    expect(html).toContain("max-h-[28rem] overflow-auto");
    expect(html).toContain("sticky top-0");
    expect(html).toContain("text-primary-navy");
    expect(html).toContain("session-25");
    expect(html).toContain("Repeated source-IP activity indicates recurrence only");
  });

  it("shows provider-specific metadata panels and bounded results without double-counting cache", () => {
    const sourceIpCache = [
      { provider: "abuseipdb", cache_key: "abuse-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { abuse_confidence_score: 100, total_reports: 1809, country_code: "SE" } },
      { provider: "otx", cache_key: "otx-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { pulses: [{ pulse_id: "p1", name: "Observed SSH scanner feed" }], truncated: false } },
      { provider: "shodan_official", cache_key: "shodan-1", lookup_status: "OK", lookup_at: "2026-09-23T19:13:25Z", expires_at: "2026-09-24T19:13:25Z", normalized_context: { ports: [22, 80], service_product_summary: ["ssh 22", "nginx 80"] } },
    ];
    const html = renderToStaticMarkup(<ExternalTiSummary
      sessionData={{ status: "TI_AVAILABLE", counts: { eligible_observables: 1 }, source_ip_cache: sourceIpCache }}
      observableData={{ source_ip_cache: sourceIpCache, observable: { value: "203.0.113.9" } }}
    />);
    expect(html).toContain("Provider Intelligence");
    expect(html).toContain("abuse score");
    expect(html).toContain("community reports");
    expect(html).toContain("1809");
    expect(html).toContain("pulse matches");
    expect(html).toContain("Observed SSH scanner feed");
    expect(html).toContain("ports");
    expect(html).toContain("ssh 22, nginx 80");
    expect(html).toContain("not necessarily observed in this Cowrie session");
    expect(html).toContain("3 source-IP provider lookup results");
    expect(html).toContain("max-h-[620px] overflow-y-auto");
    expect(html).toContain("lg:grid-cols-2");
    expect(html).toContain("Technical details");
    expect(html).not.toMatch(/<details[^>]*open(?:=|\s|>)/);
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
    expect(html).toContain("its selected ID belongs to response guidance");
    expect(html).toContain("Existing action selected for review");
  });

  it("resolves canonical and response-guidance AI selections from their distinct ledgers", () => {
    const html = renderToStaticMarkup(<AiAdvisorySummary
      data={{ status: "accepted", advisory: { validated_advisory: {
        selected_finding_ids: ["canonical-1", "guidance-1"], ranked_action_ids: ["action-1"],
      } } }}
      behavioralFindings={[{ finding_id: "canonical-1", statement: "Observed transfer event" }]}
      guidanceData={{ response_guidance: {
        findings: [{ finding_id: "guidance-1", statement: "Review download evidence" }],
        advisory_actions: [{ action_id: "action-1", description: "Preserve logs" }],
      } }}
    />);
    expect(html).toContain("Observed transfer event");
    expect(html).toContain("Review download evidence");
    expect(html).toContain("Canonical behavioral finding");
    expect(html).not.toContain("Some AI selections could not be matched");
  });

  it("uses a canonical ID-only fallback when the active backend has not exposed finding details", () => {
    const html = renderToStaticMarkup(<AiAdvisorySummary
      data={{ advisory: { validated_advisory: { selected_finding_ids: ["canonical-older"] } } }}
      guidanceData={{ response_guidance: { findings: [] } }}
      canonicalFindingIds={["canonical-older"]}
    />);
    expect(html).toContain("Canonical behavioral finding recorded in the immutable assessment");
    expect(html).toContain("canonical-older");
    expect(html).not.toContain("Some AI selections could not be matched");
  });

  it("does not present disabled provider records as fresh intelligence", () => {
    const html = renderToStaticMarkup(<ExternalTiSummary
      sessionData={{ status: "TI_PENDING", status_reason_text: "Provider policy blocked", freshness: { state: "TI_FRESH" }, evidence: [
        { provider: "otx", lookup_status: "DISABLED", freshness_state: "FRESH" },
      ] }} observableData={{}} />);
    expect(html).toContain("No provider lookup was executed");
    expect(html).toMatch(/Providers with results<\/dt><dd[^>]*>0<\/dd>/);
    expect(html).not.toContain("ti fresh");
    expect(html).not.toContain("freshness: FRESH");
    expect(html).toContain("Last lookup: Not executed");
    expect(html).toContain("No provider lookup was executed");
    expect(html).toContain("Lookup status");
    expect(html).toContain("AlienVault OTX");
    expect(html).not.toContain("Recorded Not recorded · provider not queried");
  });

  it("distinguishes a provider error from an unexecuted lookup", () => {
    const html = renderToStaticMarkup(<ExternalTiSummary
      sessionData={{ status: "TI_AVAILABLE", counts: { eligible_observables: 1 }, provider_status: {
        otx: { lookup_status: "PROVIDER_ERROR", record_count: 1, lookup_at: "2026-09-27T10:00:00Z" },
      } }}
      observableData={{ observable: { value: "203.0.113.9" } }}
    />);

    expect(html).toContain("Provider error");
    expect(html).toContain("Provider records");
    expect(html).toContain("Provider lookup returned Provider error");
    expect(html).not.toContain("No provider lookup was executed");
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
    expect(html).toContain("it did not corroborate or change the Model1 recommendation");
  });

  it("distinguishes raw Model2 agreement from an evidence-qualified vote", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-v1",
      ensemble_evidence: {
        model1: { applicable: true }, model2: { available: true },
        results: [{ technique_id: "T1105", evidence_state: "AGREE", model1_result: "PRESENT", model2_result: "PRESENT" }],
      },
      session_ttp_advisory: { weighted_voting_recommendation: { rows: [{
        technique_id: "T1105", model2_support_added: false,
        exclusion_reason: "t1105_session_bound_transfer_evidence_required",
      }] } },
    }} />);
    expect(html).toContain("RAW AGREE · NO VOTE");
    expect(html).toContain("did not vote or change the recommendation");
    expect(html).toContain("t1105 session bound transfer evidence required");
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
