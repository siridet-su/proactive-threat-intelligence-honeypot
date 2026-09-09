import { describe, expect, it } from "vitest";
import { hardwareTelemetryFromMongoDocument } from "../src/lib/hardware-mongo";

describe("hardwareTelemetryFromMongoDocument", () => {
  it("accepts a hardware live document with a BSON date", () => {
    const timestamp = new Date("2026-09-10T00:00:00Z");
    const document = {
      _id: "pi-1:0",
      sensor_id: "pi-1",
      timestamp,
      cpu_percent: 12.5,
      mem_percent: 25,
    };

    const result = hardwareTelemetryFromMongoDocument(document);

    expect(result).toEqual(document);
    expect(result?.timestamp).toBe(timestamp);
  });

  it("rejects a document without hardware telemetry fields", () => {
    expect(hardwareTelemetryFromMongoDocument({
      _id: "pi-1:0",
      sensor_id: "pi-1",
    })).toBeNull();
  });
});
