import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { projectAdminCommandRecords } from "@/lib/session-command-projection";
import { authenticatedSensorSessionAlias } from "@/lib/sensor-session-identity";

const SENSOR_ID = "pi-cowrie-01";
const SENSOR_SESSION_ID = "09afe59d1a00";
const CANONICAL_SESSION_ID = `session_v1_${createHash("sha256")
  .update(JSON.stringify({
    schema_version: "authenticated_sensor_session.v1",
    sensor_id: SENSOR_ID,
    sensor_session_id: SENSOR_SESSION_ID,
  }))
  .digest("hex")
  .slice(0, 32)}`;

describe("authenticated Cowrie sensor/session binding", () => {
  const event = {
    eventid: "cowrie.command.input",
    session: CANONICAL_SESSION_ID,
    sensor_id: SENSOR_ID,
    _honeypot_identity: {
      schema_version: "authenticated_sensor_session.v1",
      sensor_id: SENSOR_ID,
      sensor_session_id: SENSOR_SESSION_ID,
      canonical_session_id: CANONICAL_SESSION_ID,
    },
  };

  it("accepts only a recomputed canonical ID and returns the bound sensor-local ID", () => {
    expect(authenticatedSensorSessionAlias(CANONICAL_SESSION_ID, event, SENSOR_ID)).toBe(SENSOR_SESSION_ID);
    expect(authenticatedSensorSessionAlias(CANONICAL_SESSION_ID, event, "other-sensor")).toBeNull();
    expect(authenticatedSensorSessionAlias("session_v1_00000000000000000000000000000000", event, SENSOR_ID)).toBeNull();
  });

  it("rejects identity fields with control characters or an unbound payload session", () => {
    expect(authenticatedSensorSessionAlias(CANONICAL_SESSION_ID, {
      ...event,
      session: "session_v1_00000000000000000000000000000000",
    }, SENSOR_ID)).toBeNull();
    expect(authenticatedSensorSessionAlias(CANONICAL_SESSION_ID, {
      ...event,
      _honeypot_identity: { ...event._honeypot_identity, sensor_session_id: "bad\nidentifier" },
    }, SENSOR_ID)).toBeNull();
  });
});

describe("Admin command evidence projection", () => {
  it("retains exact command input but projects no structured credentials or whole event payload", () => {
    const input = "curl -u attacker:synthetic-pass --password=synthetic-pass https://example.invalid/";
    const result = projectAdminCommandRecords(
      CANONICAL_SESSION_ID,
      {
        session_id: CANONICAL_SESSION_ID,
        events: [{ event_id: "evt-1", eventid: "cowrie.command.input", command_event: true }],
        classification_events: [{
          evidence_id: "evidence-1",
          ttp: "T1105",
          durable_evidence_order: { event_id: "evt-1" },
        }],
      },
      {
        session_id: CANONICAL_SESSION_ID,
        commands: [{
          event_id: "evt-1",
          eventid: "cowrie.command.input",
          timestamp: "2026-09-21T13:36:14.000Z",
          input,
          password: "must-not-be-projected",
          username: "must-not-be-projected",
          whole_event: { input },
        }],
      },
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ input, command_text_available: true, sensitive: true, classification_technique: "T1105" });
    expect(JSON.stringify(result)).not.toContain("must-not-be-projected");
    expect(JSON.stringify(result)).not.toContain("whole_event");
  });

  it("rejects unsupported event types and does not attach a command from another session", () => {
    const result = projectAdminCommandRecords(
      CANONICAL_SESSION_ID,
      { session_id: CANONICAL_SESSION_ID },
      {
        session_id: "session_v1_00000000000000000000000000000000",
        commands: [
          { event_id: "evt-1", eventid: "cowrie.login.success", input: "secret" },
          { event_id: "evt-2", eventid: "cowrie.command.input", input: "secret" },
        ],
      },
    );
    expect(result).toHaveLength(0);
  });
});
