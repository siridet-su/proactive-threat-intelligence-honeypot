import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Model2EnsembleSummary } from "../src/components/threat/SessionAnalysisPanels";

describe("Model1 + Model2 advisory ranking panel", () => {
  it("shows joint support first without calling the priority score a probability", () => {
    const html = renderToStaticMarkup(<Model2EnsembleSummary data={{
      session_id: "session-a",
      ensemble_evidence: {
        run_id: "run-a",
        model1: { applicable: true },
        model2: {
          available: true,
          status: "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW",
          artifact_sha256: "artifact",
          feature_contract_sha256: "features",
          measurement_id: "measurement-a",
          episode_id: "episode-a",
          binding: { session_id: "session-a", run_id: "run-a", measurement_id: "measurement-a", episode_id: "episode-a" },
        },
        results: [
          { technique_id: "T1105", model1_result: "PRESENT", model1_margin: 3, model2_result: "ABSENT" },
          { technique_id: "T1110", model1_result: "PRESENT", model1_margin: 2, model2_result: "PRESENT" },
        ],
      },
    }} />);
    expect(html).toContain("TTPs to investigate first");
    expect(html).toContain("RRF · k=60");
    expect(html).toContain("priority score 0.0325");
    expect(html).toContain("Both models");
    expect(html).toContain("Models disagree");
    expect(html.indexOf("#1 <span class=\"font-mono\">T1110")).toBeGreaterThan(-1);
    expect(html).not.toContain("confidence 3.25%");
  });
});
