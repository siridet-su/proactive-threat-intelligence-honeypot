export type MapCoordinates = [longitude: number, latitude: number];

export type MapView = {
  coordinates: MapCoordinates;
  zoom: number;
};

export type GeolocatedOrigin = {
  coordinates: MapCoordinates;
};

export const DEFAULT_ORIGIN_MAP_VIEW: MapView = {
  coordinates: [0, 20],
  zoom: 1,
};

const MAP_WIDTH = 800;
const MAP_HEIGHT = 800;
const PROJECTION_SCALE = 125;
const FIT_PADDING = 70;
// At the 800×800 / scale-125 projection this frames roughly 46° of longitude:
// regional context, without the continent-wide view that exposed Brazil and Africa.
const SINGLE_ORIGIN_ZOOM = 8;
const MAX_AUTOMATIC_ZOOM = 8;
const MIN_AUTOMATIC_ZOOM = 0.65;

function normalizedLongitude(longitude: number): number {
  return ((longitude % 360) + 360) % 360;
}

function longitudeBounds(longitudes: number[]): { center: number; span: number } {
  const values = longitudes.map(normalizedLongitude).sort((a, b) => a - b);
  if (values.length === 1) {
    return { center: values[0] >= 180 ? values[0] - 360 : values[0], span: 0 };
  }

  let largestGap = -1;
  let gapIndex = 0;
  for (let index = 0; index < values.length; index += 1) {
    const next = index === values.length - 1 ? values[0] + 360 : values[index + 1];
    const gap = next - values[index];
    if (gap > largestGap) {
      largestGap = gap;
      gapIndex = index;
    }
  }

  const span = Math.max(0, 360 - largestGap);
  const arcStart = values[(gapIndex + 1) % values.length];
  const center360 = normalizedLongitude(arcStart + span / 2);
  return { center: center360 >= 180 ? center360 - 360 : center360, span };
}

function mercatorY(latitude: number): number {
  const radians = Math.max(-80, Math.min(80, latitude)) * Math.PI / 180;
  return Math.log(Math.tan(Math.PI / 4 + radians / 2));
}

function inverseMercatorY(value: number): number {
  return (2 * Math.atan(Math.exp(value)) - Math.PI / 2) * 180 / Math.PI;
}

/**
 * Focus a single approximate IP geolocation at regional scale. For multiple
 * origins, fit their geographic bounds while capping zoom so city/street-level
 * precision is never implied by the dashboard.
 */
export function getOriginMapView(origins: readonly GeolocatedOrigin[]): MapView {
  if (origins.length === 0) return DEFAULT_ORIGIN_MAP_VIEW;

  const longitudes = origins.map(({ coordinates }) => coordinates[0]);
  const latitudes = origins.map(({ coordinates }) => Math.max(-80, Math.min(80, coordinates[1])));
  if (origins.length === 1) {
    return {
      coordinates: [longitudes[0], latitudes[0]],
      zoom: SINGLE_ORIGIN_ZOOM,
    };
  }

  const longitude = longitudeBounds(longitudes);
  const minY = Math.min(...latitudes.map(mercatorY));
  const maxY = Math.max(...latitudes.map(mercatorY));
  const centerY = (minY + maxY) / 2;
  const width = longitude.span * Math.PI / 180 * PROJECTION_SCALE;
  const height = (maxY - minY) * PROJECTION_SCALE;
  const availableWidth = MAP_WIDTH - FIT_PADDING * 2;
  const availableHeight = MAP_HEIGHT - FIT_PADDING * 2;
  const zoom = Math.min(
    MAX_AUTOMATIC_ZOOM,
    Math.max(MIN_AUTOMATIC_ZOOM, Math.min(availableWidth / Math.max(width, 1), availableHeight / Math.max(height, 1))),
  );

  return {
    coordinates: [longitude.center, inverseMercatorY(centerY)],
    zoom,
  };
}
