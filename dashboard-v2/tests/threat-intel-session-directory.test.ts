import { describe, expect, it } from "vitest";
import {
  attackerTypeQueryValue,
  buildSessionDirectoryRows,
  SESSION_ATTACKER_TYPE_OPTIONS,
} from "@/lib/threat-intel-session-directory";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";
import type { WebHttpSession } from "@/lib/web-http-intel";

const sshSession: DashboardThreatEvent = {
  id: "ssh-session-1",
  timestamp: "2026-09-27T12:00:00.000Z",
  date: "27/09/2026",
  time: "12:00:00 UTC",
  sensor: "pi-cowrie-01",
  src_ip: "198.51.100.10",
  sourceIp: "198.51.100.10",
  severity: "Medium",
  classification: "Unknown",
  typeColor: "",
  duration: "Closed",
  end_time: "2026-09-27T12:00:24.000Z",
  session_status: "closed",
  geo: { lat: 37.5, lon: 127.5, country: "KR", city: "Unknown" },
};

const httpSession: WebHttpSession = {
  id: "a".repeat(32),
  events: [
    {
      eventId: "http-event-1",
      sessionId: "a".repeat(32),
      eventType: "web_http_request",
      observedAt: "2026-09-27T12:01:00.000Z",
      sourceIp: "203.0.113.20",
      sourcePort: 51_000,
      destinationIp: "10.0.0.1",
      destinationPort: 80,
      transport: "tcp",
      service: "http",
      method: "GET",
      path: "/login",
      statusCode: 200,
      outcome: "unknown",
      signals: ["xss"],
      ruleIds: ["xss_script_tag"],
      matches: [],
      ttpCandidate: "T1190",
      authority: "contextual_rule_hint_only",
      modelPrediction: false,
      exploitConfirmed: false,
    },
    {
      eventId: "http-event-2",
      sessionId: "a".repeat(32),
      eventType: "web_http_request",
      observedAt: "2026-09-27T12:01:05.000Z",
      sourceIp: "203.0.113.20",
      sourcePort: 51_000,
      destinationIp: "10.0.0.1",
      destinationPort: 80,
      transport: "tcp",
      service: "http",
      method: "POST",
      path: "/web/login",
      statusCode: 401,
      outcome: "rejected",
      signals: [],
      ruleIds: [],
      matches: [],
      ttpCandidate: null,
      authority: "contextual_rule_hint_only",
      modelPrediction: false,
      exploitConfirmed: false,
    },
  ],
  firstObservedAt: "2026-09-27T12:01:00.000Z",
  lastObservedAt: "2026-09-27T12:01:05.000Z",
  sourceIps: ["203.0.113.20"],
};

describe("unified session directory projection", () => {
  it("preserves exactly the backend-supported attacker types and scopes them to SSH", () => {
    expect(SESSION_ATTACKER_TYPE_OPTIONS).toEqual([
      { value: "APT", label: "APT" },
      { value: "Bot", label: "Bot" },
      { value: "ScriptKiddie", label: "Script Kiddie" },
    ]);
    expect(attackerTypeQueryValue("ssh", "APT")).toBe("APT");
    expect(attackerTypeQueryValue("ssh", "ScriptKiddie")).toBe("ScriptKiddie");
    expect(attackerTypeQueryValue("all", "APT")).toBeNull();
    expect(attackerTypeQueryValue("http", "APT")).toBeNull();
    expect(attackerTypeQueryValue("ssh", "All")).toBeNull();
  });

  it("merges SSH and HTTP while keeping protocol-specific destinations and fields", () => {
    const rows = buildSessionDirectoryRows([sshSession], [httpSession], "all");

    expect(rows.map((row) => row.protocol)).toEqual(["HTTP", "SSH"]);
    expect(rows[0]).toMatchObject({
      href: `/threat-intel/http/${"a".repeat(32)}`,
      sensor: "web-corp",
      activity: "2 requests · 1 injection hint",
      dwellTime: "5s observed",
      status: "Observed",
    });
    expect(rows[1]).toMatchObject({
      href: "/threat-intel/ssh-session-1",
      sensor: "pi-cowrie-01",
      activity: "Command activity",
      dwellTime: "24s",
      status: "Closed",
    });
  });

  it("filters each protocol and searches safe HTTP method/path hints", () => {
    expect(buildSessionDirectoryRows([sshSession], [httpSession], "ssh")).toHaveLength(1);
    expect(buildSessionDirectoryRows([sshSession], [httpSession], "http")).toHaveLength(1);
    expect(buildSessionDirectoryRows([sshSession], [httpSession], "all", "/web/login").map((row) => row.protocol))
      .toEqual(["HTTP"]);
  });

  it("does not invent an HTTP status or location precision", () => {
    const row = buildSessionDirectoryRows([], [httpSession], "http")[0];
    expect(row.status).toBe("Observed");
    expect(row.originDetail).toBe("Location unavailable");
  });
});
