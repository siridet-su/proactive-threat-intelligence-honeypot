import { describe, expect, it } from "vitest";
import { DEFAULT_ORIGIN_MAP_VIEW, getOriginMapView } from "@/lib/threat-intel-map-view";

describe("origin map viewport", () => {
  it("keeps the world view when no geolocated origin is available", () => {
    expect(getOriginMapView([])).toEqual(DEFAULT_ORIGIN_MAP_VIEW);
  });

  it("focuses one Korean origin on Korea and nearby East Asia at regional zoom", () => {
    const view = getOriginMapView([{ coordinates: [127.5, 37.5] }]);

    expect(view.coordinates).toEqual([127.5, 37.5]);
    expect(view.zoom).toBeGreaterThanOrEqual(4);
    expect(view.zoom).toBeLessThan(4.5);
  });

  it("fits multiple origins and handles the dateline using the short longitude arc", () => {
    const eastAsia = getOriginMapView([
      { coordinates: [127.5, 37.5] },
      { coordinates: [139.7, 35.7] },
      { coordinates: [121.5, 25] },
    ]);
    expect(eastAsia.zoom).toBeLessThanOrEqual(4.5);
    expect(eastAsia.coordinates[0]).toBeGreaterThan(120);
    expect(eastAsia.coordinates[0]).toBeLessThan(140);

    const dateline = getOriginMapView([
      { coordinates: [179, 10] },
      { coordinates: [-179, 12] },
    ]);
    expect(Math.abs(dateline.coordinates[0])).toBeGreaterThan(175);
    expect(dateline.zoom).toBeGreaterThan(1);
  });
});
