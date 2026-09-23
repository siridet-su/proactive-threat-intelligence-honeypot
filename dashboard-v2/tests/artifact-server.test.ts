import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Db, Document } from "mongodb";

vi.mock("server-only", () => ({}));

import {
  getArtifactPage,
  mapLegacyEnrichmentRecord,
  mapThreatIntelRecord,
  normalizeSha256,
} from "@/lib/artifact-server";

function cursor(documents: Document[]) {
  let selected = [...documents];
  const value = {
    sort: () => value,
    skip: (amount: number) => {
      selected = selected.slice(amount);
      return value;
    },
    limit: (amount: number) => {
      selected = selected.slice(0, amount);
      return value;
    },
    maxTimeMS: () => value,
    toArray: async () => selected,
  };
  return value;
}

function fakeDatabase(
  name: string,
  documents: Record<string, Document[]>,
  counts: Record<string, number[]>,
): Db {
  const countIndexes = new Map<string, number>();
  return {
    databaseName: name,
    collection: ((collectionName: string) => {
      const rows = documents[collectionName] ?? [];
      return {
        createIndex: vi.fn().mockResolvedValue("index"),
        countDocuments: vi.fn(async () => {
          const index = countIndexes.get(collectionName) ?? 0;
          countIndexes.set(collectionName, index + 1);
          const configured = counts[collectionName] ?? [];
          return configured[index] ?? configured.at(-1) ?? 0;
        }),
        find: vi.fn(() => cursor(rows)),
      };
    }) as Db["collection"],
  } as unknown as Db;
}

const HASH = "a".repeat(64);

describe("artifact intelligence projection", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("accepts only canonical SHA-256 values", () => {
    expect(normalizeSha256(HASH.toUpperCase())).toBe(HASH);
    expect(normalizeSha256("b".repeat(63))).toBeNull();
    expect(normalizeSha256("z".repeat(64))).toBeNull();
  });

  it("maps provider results without confusing a provider hash with an artifact hash", () => {
    const record = mapThreatIntelRecord({
      _id: "job-1",
      observable: HASH,
      status: "complete",
      summary: {
        known_to_provider: true,
        meaningful_name: "Example.Loader",
        analysis_stats: { malicious: 4, suspicious: 1, undetected: 60 },
      },
      queried_at: "2026-09-23T00:00:00.000Z",
      expires_at: "2099-09-23T00:00:00.000Z",
    }, new Date("2026-09-23T01:00:00.000Z"));

    expect(record?.hash).toBe(HASH);
    expect(record?.intel.status).toBe("known_malicious");
    expect(record?.intel.detectionRatio).toBe("5/65");
    expect(record?.intel.malwareFamily).toBe("Example.Loader");
  });

  it("treats not-found and expired provider responses as unknown/stale", () => {
    const notFound = mapThreatIntelRecord({
      _id: "job-2",
      observable: HASH,
      status: "not_found",
      summary: { known_to_provider: false },
    }, new Date("2026-09-23T01:00:00.000Z"));
    const stale = mapThreatIntelRecord({
      _id: "job-3",
      observable: HASH,
      status: "complete",
      summary: { known_to_provider: true },
      expires_at: "2026-09-22T00:00:00.000Z",
    }, new Date("2026-09-23T01:00:00.000Z"));

    expect(notFound?.intel.status).toBe("unknown_to_provider");
    expect(stale?.intel.status).toBe("stale");
  });

  it("uses the legacy observable identity and never returns payload_sha256 as the artifact hash", () => {
    const record = mapLegacyEnrichmentRecord({
      _id: "legacy-1",
      observable_type: "hash",
      observable_value: HASH,
      payload_sha256: "f".repeat(64),
      provider_status_json: JSON.stringify({
        virustotal: { status: "not_found", vt_hit: false },
      }),
    }, new Date("2026-09-23T01:00:00.000Z"));

    expect(record?.hash).toBe(HASH);
    expect(record?.hash).not.toBe("f".repeat(64));
    expect(record?.intel.status).toBe("unknown_to_provider");
  });

  it("reads Pi threat_intel records and only projects bounded event metadata", async () => {
    const database = fakeDatabase(
      "artifact-threat-intel",
      {
        threat_intel: [{
          _id: "job-4",
          provider: "virustotal",
          observable_type: "sha256",
          observable: HASH,
          status: "complete",
          summary: { known_to_provider: false },
          queried_at: "2026-09-23T00:00:00.000Z",
        }],
        events: [{
          _id: "event-1",
          timestamp: "2026-09-22T23:00:00.000Z",
          network: { src_ip: "203.0.113.10" },
          session: { id: "session-1" },
          activity: { filename: "dropper.bin", size_bytes: 1234, url: "https://example.test/drop?download-token=secret-token#fragment" },
          threat_intel: { virustotal: { observable: HASH } },
          raw: { payload: { sha256: HASH, secret: "must-not-leak" } },
        }],
      },
      { threat_intel: [1, 1] },
    );

    const page = await getArtifactPage(database, { limit: 25, now: new Date("2026-09-23T01:00:00.000Z") });
    expect(page.dataSource).toBe("threat_intel");
    expect(page.items[0]).toMatchObject({
      artifactSha256: HASH,
      sourceIps: ["203.0.113.10"],
      sessionIds: ["session-1"],
      observedFilename: "dropper.bin",
      sizeBytes: 1234,
    });
    expect(JSON.stringify(page)).not.toContain("secret");
    expect(JSON.stringify(page)).not.toContain("download-token");
    expect(JSON.stringify(page)).not.toContain("payload_sha256");
  });

  it("surfaces a hash from an event as pending when no TI worker record exists", async () => {
    const database = fakeDatabase(
      "artifact-event-fallback",
      {
        events: [{
          _id: "event-2",
          timestamp: "2026-09-23T00:00:00.000Z",
          network: { src_ip: "198.51.100.20" },
          raw: { payload: { sha256: HASH } },
        }],
      },
      { threat_intel: [0], enrichment_records: [0] },
    );

    const page = await getArtifactPage(database, { limit: 25, now: new Date("2026-09-23T01:00:00.000Z") });
    expect(page.dataSource).toBe("events");
    expect(page.items[0]?.intel.status).toBe("pending");
    expect(page.items[0]?.artifactSha256).toBe(HASH);
  });
});
