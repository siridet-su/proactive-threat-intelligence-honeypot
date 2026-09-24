import { describe, expect, it } from "vitest";
import { projectWebHttpEvent } from "@/lib/web-http-intel";

function event(overrides: Record<string, unknown> = {}) {
  return {
    source: "web-corp", event_type: "web_login_attempt", event_id: "abc123",
    timestamp: "2026-09-24T10:00:00Z", outcome: "rejected",
    network: { src_ip: "198.51.100.8" },
    http: { method: "POST", path: "/web/login", query: "" },
    ...overrides,
  };
}

describe("Web-corp read-only HTTP hints", () => {
  it("projects existing SQLi indicators without leaking login values or claiming an exploit", () => {
    const input = event({
      web_login: { password: "synthetic-secret", username: "hidden@example.invalid" },
      raw: { payload: { odoo_login: { password: "synthetic-secret" } } },
      analysis: { sqli: { indicators: { password: ["boolean_tautology", "sql_comment", "forged_rule"] } } },
    });
    const output = projectWebHttpEvent(input);
    expect(output?.signals).toEqual(["sqli"]);
    expect(output?.ruleIds).toEqual(["sqli_boolean_tautology", "sqli_sql_comment"]);
    expect(output?.ttpCandidate).toBe("T1190");
    expect(output?.exploitConfirmed).toBe(false);
    expect(output?.modelPrediction).toBe(false);
    expect(JSON.stringify(output)).not.toContain("synthetic-secret");
    expect(JSON.stringify(output)).not.toContain("hidden@example.invalid");
  });

  it("detects bounded URL XSS patterns without returning the submitted URL", () => {
    const output = projectWebHttpEvent(event({ http: { method: "GET", path: "/web/login", query: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" } }));
    expect(output?.signals).toEqual(["xss"]);
    expect(output?.ruleIds).toEqual(["xss_script_tag"]);
    expect(JSON.stringify(output)).not.toContain("alert(1)");
    expect(JSON.stringify(output)).not.toContain("%3Cscript");
    expect(output?.ttpCandidate).toBe("T1190");
  });

  it("does not invent a TTP from an ordinary rejected login", () => {
    const output = projectWebHttpEvent(event());
    expect(output?.signals).toEqual([]);
    expect(output?.ttpCandidate).toBeNull();
  });

  it("rejects other sources and event types", () => {
    expect(projectWebHttpEvent(event({ source: "cowrie" }))).toBeNull();
    expect(projectWebHttpEvent(event({ event_type: "web_event" }))).toBeNull();
  });
});
