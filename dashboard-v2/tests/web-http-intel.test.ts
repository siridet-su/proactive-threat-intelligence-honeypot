import { describe, expect, it } from "vitest";
import { groupWebHttpSessions, projectWebHttpEvent } from "@/lib/web-http-intel";

function event(overrides: Record<string, unknown> = {}) {
  return {
    source: "web-corp", event_type: "web_login_attempt", event_id: "abc123",
    timestamp: "2026-09-24T10:00:00Z", outcome: "rejected",
    network: { src_ip: "198.51.100.8", src_port: 49152 },
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

  it("shows sensor XSS indicator from a form field without returning the submitted URL or value", () => {
    const output = projectWebHttpEvent(event({
      http: { method: "POST", path: "/web/login", query: "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
      analysis: { xss: { indicators: { login: ["script_tag"] } } },
    }));
    expect(output?.signals).toEqual(["xss"]);
    expect(output?.ruleIds).toEqual(["xss_script_tag"]);
    expect(output?.matches).toContainEqual({ signal: "xss", field: "login", ruleId: "script_tag" });
    expect(JSON.stringify(output)).not.toContain("alert(1)");
    expect(JSON.stringify(output)).not.toContain("%3Cscript");
    expect(output?.ttpCandidate).toBe("T1190");
  });

  it("does not invent a TTP from an ordinary rejected login", () => {
    const output = projectWebHttpEvent(event());
    expect(output?.signals).toEqual([]);
    expect(output?.ttpCandidate).toBeNull();
  });

  it("projects a captured TCP source port as connection metadata", () => {
    expect(projectWebHttpEvent(event())?.sourcePort).toBe(49152);
  });

  it("rejects other sources and event types", () => {
    expect(projectWebHttpEvent(event({ source: "cowrie" }))).toBeNull();
    expect(projectWebHttpEvent(event({ event_type: "web_event" }))).toBeNull();
  });

  it("groups only sensor-issued browser-continuity IDs, never shared IPs", () => {
    const first = projectWebHttpEvent(event({
      event_id: "first", event_type: "web_http_request", outcome: "",
      correlation: { web_session_id: "0123456789abcdef0123456789abcdef" },
      http: { method: "GET", path: "/login.html", status_code: 200 },
    }))!;
    const second = projectWebHttpEvent(event({
      event_id: "second", correlation: { web_session_id: "0123456789abcdef0123456789abcdef" },
    }))!;
    const legacy = projectWebHttpEvent(event({ event_id: "legacy" }))!;
    const grouped = groupWebHttpSessions([first, second, legacy]);
    expect(grouped).toHaveLength(2);
    expect(grouped.find((group) => group.id)?.events).toHaveLength(2);
    expect(grouped.find((group) => group.id === null)?.events).toHaveLength(1);
  });
});
