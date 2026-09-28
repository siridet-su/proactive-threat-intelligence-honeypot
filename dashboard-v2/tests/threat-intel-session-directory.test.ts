import { describe, expect, it } from "vitest";
import {
  attackerTypeQueryValue,
  buildSessionDirectoryRows,
  calculateDirectoryPagination,
  normalizeAttackerType,
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
  classification: "Bot",
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
  it("preserves exactly the backend-supported attacker types and queries them when applicable", () => {
    expect(SESSION_ATTACKER_TYPE_OPTIONS).toEqual([
      { value: "APT", label: "APT" },
      { value: "Bot", label: "Bot" },
      { value: "ScriptKiddie", label: "Script Kiddie" },
      { value: "Unknown", label: "Unknown" },
    ]);
    expect(attackerTypeQueryValue("ssh", "APT")).toBe("APT");
    expect(attackerTypeQueryValue("ssh", "ScriptKiddie")).toBe("ScriptKiddie");
    expect(attackerTypeQueryValue("ssh", "Unknown")).toBe("Unknown");
    expect(attackerTypeQueryValue("all", "APT")).toBe("APT");
    expect(attackerTypeQueryValue("http", "APT")).toBeNull();
    expect(attackerTypeQueryValue("ssh", "All")).toBeNull();
    expect(attackerTypeQueryValue("all", "All")).toBeNull();
  });

  it("filters sessions by attacker type including Unknown for HTTP and unclassified SSH", () => {
    const aptRows = buildSessionDirectoryRows([sshSession], [httpSession], "all", "", "APT");
    expect(aptRows).toHaveLength(0);

    const botRows = buildSessionDirectoryRows([sshSession], [httpSession], "all", "", "Bot");
    expect(botRows).toHaveLength(1);
    expect(botRows[0].id).toBe("ssh-session-1");

    const unknownRows = buildSessionDirectoryRows([sshSession], [httpSession], "all", "", "Unknown");
    expect(unknownRows).toHaveLength(1);
    expect(unknownRows[0].protocol).toBe("HTTP");
    expect(unknownRows[0].attackerType).toBe("Unknown");
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
      attackerType: "Bot",
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

  it("uses only supported attacker categories and leaves unknown labels as Unknown", () => {
    expect(normalizeAttackerType("APT")).toBe("APT");
    expect(normalizeAttackerType("ScriptKiddie")).toBe("ScriptKiddie");
    expect(normalizeAttackerType("untrusted value")).toBe("Unknown");
    expect(normalizeAttackerType(null)).toBe("Unknown");
    const [row] = buildSessionDirectoryRows([{ ...sshSession, classification: "Untrusted value" }], [], "ssh");
    expect(row.attackerType).toBe("Unknown");
  });

  it("does not invent an HTTP status or location precision", () => {
    const row = buildSessionDirectoryRows([], [httpSession], "http")[0];
    expect(row.status).toBe("Observed");
    expect(row.originDetail).toBe("Location unavailable");
  });

  describe("calculateDirectoryPagination", () => {
    it("includes both HTTP and SSH in total sessions, pages, and respects rows per page limit in all view", () => {
      // 5 HTTP sessions, 20 SSH sessions, pageSize = 15
      const page1 = calculateDirectoryPagination(20, 5, "all", 15, 1);
      expect(page1).toEqual({
        totalSessions: 25,
        totalPages: 2,
        page: 1,
        pageSize: 15,
        httpOffset: 0,
        httpLimit: 5,
        sshOffset: 0,
        sshLimit: 10,
      });
      // Sum of items on page 1 is exactly 15 (pageSize)
      expect(page1.httpLimit + page1.sshLimit).toBe(15);

      const page2 = calculateDirectoryPagination(20, 5, "all", 15, 2);
      expect(page2).toEqual({
        totalSessions: 25,
        totalPages: 2,
        page: 2,
        pageSize: 15,
        httpOffset: 0,
        httpLimit: 0,
        sshOffset: 10,
        sshLimit: 15,
      });
      // Page 2 displays the next 15 SSH items
      expect(page2.httpLimit + page2.sshLimit).toBe(15);
    });

    it("paginates HTTP sessions correctly and sets sshLimit to 0 in http view", () => {
      const page1 = calculateDirectoryPagination(50, 20, "http", 15, 1);
      expect(page1).toEqual({
        totalSessions: 20,
        totalPages: 2,
        page: 1,
        pageSize: 15,
        httpOffset: 0,
        httpLimit: 15,
        sshOffset: 0,
        sshLimit: 0,
      });

      const page2 = calculateDirectoryPagination(50, 20, "http", 15, 2);
      expect(page2).toEqual({
        totalSessions: 20,
        totalPages: 2,
        page: 2,
        pageSize: 15,
        httpOffset: 15,
        httpLimit: 5,
        sshOffset: 0,
        sshLimit: 0,
      });
    });

    it("paginates SSH sessions correctly and sets httpLimit to 0 in ssh view", () => {
      const page1 = calculateDirectoryPagination(30, 10, "ssh", 15, 1);
      expect(page1).toEqual({
        totalSessions: 30,
        totalPages: 2,
        page: 1,
        pageSize: 15,
        httpOffset: 0,
        httpLimit: 0,
        sshOffset: 0,
        sshLimit: 15,
      });

      const page2 = calculateDirectoryPagination(30, 10, "ssh", 15, 2);
      expect(page2).toEqual({
        totalSessions: 30,
        totalPages: 2,
        page: 2,
        pageSize: 15,
        httpOffset: 0,
        httpLimit: 0,
        sshOffset: 15,
        sshLimit: 15,
      });
    });

    it("clamps requested page number to safe boundary [1, totalPages]", () => {
      const clampedHigh = calculateDirectoryPagination(10, 5, "all", 15, 99);
      expect(clampedHigh.page).toBe(1);
      expect(clampedHigh.totalPages).toBe(1);

      const clampedLow = calculateDirectoryPagination(10, 5, "all", 15, 0);
      expect(clampedLow.page).toBe(1);
    });
  });
});
