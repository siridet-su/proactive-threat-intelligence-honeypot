import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Model2EnsembleSummary } from "../src/components/threat/SessionAnalysisPanels";

describe("Model1 + Model2 advisory panel", () => {
  it("explains command support without claiming RRF or confidence", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-a",
      session_ttp_advisory: {
        schema_version: "session_model1_ttp_advisory.v1", session_id: "session-a", authority: "ADVISORY_ONLY",
        assessed_command_events: 5,
        techniques: [
          { technique_id: "T1105", supporting_command_events: 3, evidence_refs: [{ command_ref: "index:0" }] },
          { technique_id: "T1110", supporting_command_events: 2, evidence_refs: [{ command_ref: "index:1" }] },
        ],
      },
      ensemble_evidence: {
        run_id: "run-a", model1: { applicable: true },
        model2: { available: false, status: "INCONCLUSIVE_EXPERIMENTAL_SHADOW" },
        results: [],
      },
    }} />);
    expect(html).toContain("3 of 5 assessed command events");
    expect(html).toContain("Command refs: index:0");
    expect(html).toContain("Model2 unavailable");
    expect(html).not.toContain("RRF · k=60");
    expect(html).not.toContain("priority score");
  });
});
