import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}), { virtual: true });

import * as mongo from "@/lib/mongodb";
import { getThreatDirectory } from "@/lib/threat-server";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";
import {
  explicitlyActiveSession,
  explicitlyClosedSession,
  missingSeveritySession,
  sessionFixture,
  type Phase0SessionDocument,
} from "./fixtures/dashboard-v2-phase0";

function mockThreatDirectory(documents: Phase0SessionDocument[]) {
  const toArray = vi.fn().mockResolvedValue(documents);
  const cursor = {
    sort: vi.fn(),
    skip: vi.fn(),
    limit: vi.fn(),
    allowDiskUse: vi.fn(),
    toArray,
  };
  cursor.sort.mockReturnValue(cursor);
  cursor.skip.mockReturnValue(cursor);
  cursor.limit.mockReturnValue(cursor);
  cursor.allowDiskUse.mockReturnValue(cursor);

  const collection = {
    countDocuments: vi.fn().mockResolvedValue(documents.length),
    find: vi.fn().mockReturnValue(cursor),
  };
  const client = {
    db: vi.fn().mockReturnValue({ collection: vi.fn().mockReturnValue(collection) }),
  };

  vi.spyOn(mongo, "getMongoClient").mockResolvedValue(
    client as unknown as Awaited<ReturnType<typeof mongo.getMongoClient>>,
  );
}

async function normalizedDirectory(documents: Phase0SessionDocument[]): Promise<DashboardThreatEvent[]> {
  mockThreatDirectory(documents);
  return (await getThreatDirectory({ pageSize: documents.length || 1 })).items;
}

describe("Phase 0.1A threat and lifecycle semantic baseline", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps an explicitly active old session active", async () => {
    const [threat] = await normalizedDirectory([explicitlyActiveSession]);

    expect(threat).toMatchObject({
      id: "phase0-lifecycle-active",
      duration: "Active",
      is_ended: false,
      ended: false,
      session_status: "active",
    });
  });

  it("normalizes lifecycle.status=closed as closed without legacy end-time fields", async () => {
    const [threat] = await normalizedDirectory([explicitlyClosedSession]);

    expect(threat).toMatchObject({
      duration: "Closed",
      is_ended: true,
      ended: true,
      end_time: null,
      session_status: "closed",
    });
  });

  it("uses explicit lifecycle evidence rather than recency for active and closed state", async () => {
    const [active, closed] = await normalizedDirectory([
      explicitlyActiveSession,
      explicitlyClosedSession,
    ]);

    expect(active.session_status).toBe("active");
    expect(closed.session_status).toBe("closed");
  });

  it("preserves stable session ID, source IP, sensor, and supplied severity", async () => {
    const fixture = sessionFixture({
      session_id: "phase0-preserved-fields",
      src_ip: "203.0.113.77",
      session_source: "zeek-phase0",
      max_confirmed_severity: "High",
    });
    const [threat] = await normalizedDirectory([fixture]);

    expect(threat).toMatchObject({
      id: fixture.session_id,
      src_ip: fixture.src_ip,
      sourceIp: fixture.src_ip,
      sensor: fixture.session_source,
      severity: fixture.max_confirmed_severity,
    });
  });

  it.fails("D-01: severity alone must not create actor classifications", async () => {
    const threats = await normalizedDirectory(["Critical", "High", "Medium", "Low"].map((severity) => sessionFixture({
      session_id: "phase0-d01-severity-only",
      src_ip: "203.0.113.200",
      session_source: "cowrie-phase0",
      start_time: "2020-01-02T03:04:05.000Z",
      max_confirmed_severity: severity,
    })));

    expect(threats.map((threat) => threat.classification)).toEqual([
      "Unknown",
      "Unknown",
      "Unknown",
      "Unknown",
    ]);
  });

  it.fails("D-01: missing severity remains unknown rather than promoted to Medium", async () => {
    const [threat] = await normalizedDirectory([missingSeveritySession]);

    expect(threat.severity).toBe("Unknown");
  });
});
