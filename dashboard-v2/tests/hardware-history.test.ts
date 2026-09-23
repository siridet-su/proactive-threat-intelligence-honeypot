import { describe, expect, it } from "vitest";

import {
  downsampleHardwareHistory,
  normalizeHardwareHistoryDocument,
} from "../src/lib/hardware-history";

describe("hardware history normalization", () => {
  it("reads rollup statistics from a minute document", () => {
    const result = normalizeHardwareHistoryDocument({
      timestamp: new Date("2026-09-10T00:00:00Z"),
      sample_count: 60,
      rollup: {
        cpu_percent: { min: 10, avg: 20, max: 30 },
        mem_pressure_percent: { min: 25, avg: 27.5, max: 30 },
      },
    });

    expect(result).toEqual({
      timestamp: "2026-09-10T00:00:00.000Z",
      sample_count: 60,
      metrics: {
        cpu_percent: { min: 10, avg: 20, max: 30 },
        mem_pressure_percent: { min: 25, avg: 27.5, max: 30 },
      },
    });
  });

  it("accepts legacy top-level scalar fields without using the old collection", () => {
    const result = normalizeHardwareHistoryDocument({
      timestamp: "2026-09-10T00:01:00Z",
      cpu_percent: 12.5,
      temperature: "44.25",
    });

    expect(result?.metrics).toEqual({
      cpu_percent: { min: 12.5, avg: 12.5, max: 12.5 },
      temperature: { min: 44.25, avg: 44.25, max: 44.25 },
    });
  });
});
describe("hardware history downsampling", () => {
  it("preserves extrema and weights averages by sample count", () => {
    const from = new Date("2026-09-10T00:00:00Z");
    const to = new Date("2026-09-10T01:00:00Z");
    const result = downsampleHardwareHistory([
      {
        timestamp: "2026-09-10T00:00:05Z",
        sample_count: 60,
        metrics: { cpu_percent: { min: 10, avg: 20, max: 30 } },
      },
      {
        timestamp: "2026-09-10T00:00:35Z",
        sample_count: 120,
        metrics: { cpu_percent: { min: 5, avg: 40, max: 50 } },
      },
    ], from, to);

    expect(result.bucketSeconds).toBe(60);
    expect(result.points).toHaveLength(1);
    expect(result.points[0]).toEqual({
      timestamp: "2026-09-10T00:00:00.000Z",
      sample_count: 180,
      metrics: {
        cpu_percent: { min: 5, avg: 33.333333333333336, max: 50 },
      },
    });
  });
});
