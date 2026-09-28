"use client";

import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { LocateFixed } from "lucide-react";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";

import { RefreshStatus } from "@/components/ui/RegionState";
import { MapRadarLoader } from "@/components/ui/loaders";
import { cn } from "@/lib/utils";
import { DEFAULT_ORIGIN_MAP_VIEW, getOriginMapView, type MapView } from "@/lib/threat-intel-map-view";

interface MapMarker {
  id: string;
  name: string;
  coordinates: [number, number];
}

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function RegionalMap({
  className,
  isLoading = false,
}: {
  className?: string;
  isLoading?: boolean;
} = {}) {
  const { threats, status } = useThreatFeed();
  const [isHydrated, setIsHydrated] = useState(false);
  const [activeMarkerId, setActiveMarkerId] = useState<string | null>(null);
  const [manualPosition, setManualPosition] = useState<MapView | null>(null);
  const [svgUnitsPerCssPixel, setSvgUnitsPerCssPixel] = useState(1);
  const [tooltip, setTooltip] = useState({ show: false, content: "", x: 0, y: 0 });
  const mapContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setIsHydrated(true));
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    const element = mapContainerRef.current;
    if (!element) return;
    const measure = () => {
      if (element.clientWidth > 0) setSvgUnitsPerCssPixel(800 / element.clientWidth);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const renderedThreats = useMemo(() => isHydrated ? threats : [], [isHydrated, threats]);
  const renderedStatus = isHydrated ? status : "loading";
  const markers = useMemo<MapMarker[]>(() => {
    const origins = new Map<string, MapMarker>();
    for (const threat of renderedThreats) {
      const longitude = threat.geo?.lon;
      const latitude = threat.geo?.lat;
      const country = threat.geo?.country?.trim();
      if (
        !country || country === "Unknown" ||
        !Number.isFinite(longitude) || !Number.isFinite(latitude) ||
        longitude < -180 || longitude > 180 || latitude < -90 || latitude > 90
      ) continue;

      const id = threat.sourceIp || threat.id;
      if (origins.has(id)) continue;
      origins.set(id, {
        id,
        // IP geolocation is approximate; avoid implying city-level precision.
        name: country,
        coordinates: [longitude, latitude],
      });
    }
    return [...origins.values()];
  }, [renderedThreats]);
  const automaticPosition = useMemo(
    () => getOriginMapView(markers),
    [markers],
  );
  const position = manualPosition ?? automaticPosition;
  const renderedPosition = isHydrated ? position : DEFAULT_ORIGIN_MAP_VIEW;

  function handleZoomIn() {
    if (position.zoom >= 8) return;
    const next = { ...position, zoom: Math.min(8, position.zoom * 1.5) };
    setManualPosition(next);
  }

  function handleZoomOut() {
    if (position.zoom <= 0.65) return;
    const next = { ...position, zoom: Math.max(0.65, position.zoom / 1.5) };
    setManualPosition(next);
  }

  function handleReset() {
    setManualPosition(null);
  }

  // ใช้ onMoveEnd แทน onMove เพื่อให้ Trackpad สามารถซูมและเลื่อนได้ลื่นไหล
  const handleMoveEnd = useCallback((newPosition: {
    coordinates?: [number, number];
    zoom?: number;
  }) => {
    const [currentLongitude, currentLatitude] = position.coordinates;
    const nextCoordinates = newPosition.coordinates ?? position.coordinates;
    const nextZoom = newPosition.zoom ?? position.zoom;
    const [nextLongitude, nextLatitude] = nextCoordinates;

    // Ignore unchanged positions reported again by controlled map renders.
    if (
      currentLongitude === nextLongitude &&
      currentLatitude === nextLatitude &&
      position.zoom === nextZoom
    ) return;

    setManualPosition({ coordinates: nextCoordinates, zoom: nextZoom });
  }, [position]);

  return (
    // คง touchAction: "none" ไว้เพื่อป้องกันเบราว์เซอร์ซูมหน้าจอ
    <div
      ref={mapContainerRef}
      aria-label="Attack distribution map"
      aria-busy={renderedStatus === "loading" || renderedStatus === "refreshing"}
      className={cn("ui-map relative aspect-square h-full w-full cursor-grab bg-surface-subtle active:cursor-grabbing", className)}
      style={{ touchAction: "none" }}
    >
      <ComposableMap
        projection="geoMercator"
        width={800}
        height={800}
        projectionConfig={{ scale: 125 }}
        aria-label="Approximate attacker origin locations. Use the zoom controls to adjust the view."
        style={{ width: "100%", height: "100%" }}
      >
        <ZoomableGroup
          zoom={renderedPosition.zoom}
          center={renderedPosition.coordinates}
          onMoveEnd={handleMoveEnd} // เปลี่ยนกลับมาใช้ onMoveEnd
          minZoom={0.65}
          maxZoom={8}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => {
                const properties = geo.properties as Record<string, unknown> | null;
                const geographyName = typeof properties?.name === "string"
                  ? properties.name
                  : "Unknown region";
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    tabIndex={-1}
                    aria-label={geographyName}
                    fill="var(--map-land)"
                    stroke="var(--map-border)"
                    strokeWidth={0.75}
                    vectorEffect="non-scaling-stroke"
                    onMouseEnter={(e) => {
                      setTooltip({ show: true, content: geographyName, x: e.clientX, y: e.clientY });
                    }}
                    onMouseMove={(e) => {
                      setTooltip((prev) => ({ ...prev, x: e.clientX, y: e.clientY }));
                    }}
                    onMouseLeave={() => {
                      setTooltip({ show: false, content: "", x: 0, y: 0 });
                    }}
                    className="cursor-crosshair transition-[fill] hover:fill-[var(--map-hover)]"
                  />
                );
              })
            }
          </Geographies>

          {markers.map(({ id, name, coordinates }, index) => {
            const isActive = activeMarkerId === id;
            const label = `Approximate geolocation · ${name}`;
            return (
              <Marker
                key={id || index}
                coordinates={coordinates}
                tabIndex={0}
                aria-label={label}
                onMouseEnter={(event) => {
                  setActiveMarkerId(id);
                  setTooltip({ show: true, content: label, x: event.clientX, y: event.clientY });
                }}
                onMouseMove={(event) => setTooltip((previous) => ({ ...previous, x: event.clientX, y: event.clientY }))}
                onMouseLeave={() => {
                  setActiveMarkerId(null);
                  setTooltip({ show: false, content: "", x: 0, y: 0 });
                }}
                onFocus={(event) => {
                  const bounds = event.currentTarget.getBoundingClientRect();
                  setActiveMarkerId(id);
                  setTooltip({ show: true, content: label, x: bounds.left + bounds.width / 2, y: bounds.top });
                }}
                onBlur={() => setActiveMarkerId(null)}
              >
                <title>{label}</title>
                <g aria-hidden="true">
                  <circle r={(isActive ? 10 : 9) * svgUnitsPerCssPixel / renderedPosition.zoom} fill="var(--primary)" opacity="0.16" />
                  <circle
                    r={4 * svgUnitsPerCssPixel / renderedPosition.zoom}
                    fill="var(--primary)"
                    stroke="var(--surface)"
                    strokeWidth={1 / renderedPosition.zoom}
                  />
                </g>
              </Marker>
            );
          })}
        </ZoomableGroup>
      </ComposableMap>

      {tooltip.show && (
        <div
          role="tooltip"
          className="fixed z-[110] max-w-[min(320px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-[150%] break-words rounded-lg border border-border bg-surface-raised px-3 py-2 text-xs text-text shadow-[var(--shadow-raised)] pointer-events-none"
          style={{ top: tooltip.y, left: tooltip.x }}
        >
          {tooltip.content}
        </div>
      )}

      <div className="pointer-events-none absolute bottom-4 left-4 max-w-[calc(100%-88px)] rounded-lg border border-border bg-surface px-3 py-2 text-xs text-text-muted" role={renderedStatus === "error" ? "alert" : "status"}>
        {renderedStatus === "loading" || isLoading ? "Scanning global sensor perimeter…" : renderedStatus === "error" ? <span className="text-danger">Attack locations unavailable. Retrying automatically.</span> : renderedStatus === "refreshing" || renderedStatus === "stale" ? <RefreshStatus status={renderedStatus} /> : markers.length === 0 ? "No geolocated origins in the last successful response." : <><span>Approximate geolocation</span><span className="mx-1.5 text-border-strong" aria-hidden="true">·</span><span>Drag to explore · scroll to zoom</span></>}
      </div>
      <div className="absolute bottom-4 right-4 flex flex-col gap-2">
        <button onClick={handleZoomIn} disabled={!isHydrated || position.zoom >= 8} aria-label="Zoom in" className="ui-button h-10 w-10 text-base">+</button>
        <button onClick={handleZoomOut} disabled={!isHydrated || position.zoom <= 1} aria-label="Zoom out" className="ui-button h-10 w-10 text-base">−</button>
        <button onClick={handleReset} aria-label="Reset map view" className="ui-button h-10 w-10 p-0">
          <LocateFixed className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {(isLoading || renderedStatus === "loading") && <MapRadarLoader />}
    </div>
  );
}
