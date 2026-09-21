export interface Phase0SessionDocument {
  session_id: string;
  src_ip: string;
  session_source: string;
  start_time: string;
  max_confirmed_severity?: string;
  lifecycle?: { status: "active" | "closed" };
  is_ended?: boolean;
  ended?: boolean;
  end_time?: string;
  ended_at?: string;
  closed_at?: string;
}

export function sessionFixture(
  overrides: Partial<Phase0SessionDocument> = {},
): Phase0SessionDocument {
  const { lifecycle, ...fields } = overrides;

  return {
    session_id: "phase0-session-base",
    src_ip: "192.0.2.10",
    session_source: "cowrie-phase0",
    start_time: "2020-01-02T03:04:05.000Z",
    ...fields,
    lifecycle: lifecycle ? { ...lifecycle } : { status: "active" },
  };
}

export const criticalSeveritySession = sessionFixture({
  session_id: "phase0-severity-critical",
  src_ip: "192.0.2.11",
  max_confirmed_severity: "Critical",
});

export const highSeveritySession = sessionFixture({
  session_id: "phase0-severity-high",
  src_ip: "192.0.2.12",
  max_confirmed_severity: "High",
});

export const mediumSeveritySession = sessionFixture({
  session_id: "phase0-severity-medium",
  src_ip: "192.0.2.13",
  max_confirmed_severity: "Medium",
});

export const lowSeveritySession = sessionFixture({
  session_id: "phase0-severity-low",
  src_ip: "192.0.2.14",
  max_confirmed_severity: "Low",
});

export const missingSeveritySession = sessionFixture({
  session_id: "phase0-severity-missing",
  src_ip: "192.0.2.15",
});

export const explicitlyActiveSession = sessionFixture({
  session_id: "phase0-lifecycle-active",
  src_ip: "198.51.100.20",
  start_time: "2001-02-03T04:05:06.000Z",
  max_confirmed_severity: "Low",
  lifecycle: { status: "active" },
});

export const explicitlyClosedSession = sessionFixture({
  session_id: "phase0-lifecycle-closed",
  src_ip: "198.51.100.21",
  start_time: "2001-02-03T04:05:06.000Z",
  max_confirmed_severity: "Low",
  lifecycle: { status: "closed" },
});
