"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { LocateFixed } from "lucide-react";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";

import { RefreshStatus, type RegionStatus } from "@/components/ui/RegionState";

interface MapMarker {
  id: string;
  name: string;
  coordinates: [number, number];
  status: "failed" | "running" | "other";
}

interface MapPosition {
  coordinates: [number, number];
  zoom: number;
}

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";
const defaultPosition: MapPosition = { coordinates: [0, 20], zoom: 1 };

export default function RegionalMap() {
  const [status, setStatus] = useState<RegionStatus>("loading");
  const hasResult = useRef(false);
  const [markers, setMarkers] = useState<MapMarker[]>([]);
  const [activeMarkerId, setActiveMarkerId] = useState<string | null>(null);

  useEffect(() => {
    const fetchThreats = async () => {
      setStatus(hasResult.current ? "refreshing" : "loading");
      try {
        const res = await fetch("/api/threats");
        if (!res.ok) throw new Error("Map request failed");
        if (res.ok) {
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            const newMarkers = data.filter(isDashboardThreatEvent).map((threat) => ({
              id: threat.id,
              name: [threat.geo.city, threat.geo.country].filter(Boolean).join(" · ") || "Unknown location",
              coordinates: [threat.geo.lon, threat.geo.lat] as [number, number],
              status: threat.severity === "Critical" || threat.severity === "High" ? "failed" as const : "running" as const
            })).filter((marker) => marker.coordinates[0] !== 0 && marker.coordinates[1] !== 0);
            setMarkers(newMarkers);
            hasResult.current = true;
            setStatus("ready");
          } else {
            throw new Error("Map response unavailable");
          }
        }
      } catch {
        // The dashboard region already communicates this recoverable polling
        // failure. Server-side logging retains the diagnostic detail.
        setStatus(hasResult.current ? "stale" : "error");
      }
    };

    fetchThreats();
    const interval = setInterval(fetchThreats, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);
  const [position, setPosition] = useState(defaultPosition);
  const [tooltip, setTooltip] = useState({ show: false, content: "", x: 0, y: 0 });

  function handleZoomIn() {
    if (position.zoom >= 8) return;
    setPosition((pos) => ({ ...pos, zoom: pos.zoom * 1.5 }));
  }

  function handleZoomOut() {
    if (position.zoom <= 1) return;
    setPosition((pos) => ({ ...pos, zoom: pos.zoom / 1.5 }));
  }

  function handleReset() {
    setPosition(defaultPosition);
  }

  // ใช้ onMoveEnd แทน onMove เพื่อให้ Trackpad สามารถซูมและเลื่อนได้ลื่นไหล
  const handleMoveEnd = useCallback((newPosition: MapPosition) => {
    setPosition((currentPosition) => {
      const [currentLongitude, currentLatitude] = currentPosition.coordinates;
      const [nextLongitude, nextLatitude] = newPosition.coordinates;

      // react-simple-maps can report the controlled position again after a
      // parent render. Returning the existing object prevents that report from
      // becoming a render → effect → render loop in React 19.
      if (
        currentLongitude === nextLongitude &&
        currentLatitude === nextLatitude &&
        currentPosition.zoom === newPosition.zoom
      ) {
        return currentPosition;
      }

      return newPosition;
    });
  }, []);

  return (
    // คง touchAction: "none" ไว้เพื่อป้องกันเบราว์เซอร์ซูมหน้าจอ
    <div aria-label="Attack distribution map" aria-busy={status === "loading" || status === "refreshing"} className="ui-map relative h-full w-full cursor-grab bg-surface-subtle active:cursor-grabbing" style={{ touchAction: "none" }}>
      <ComposableMap
        projection="geoMercator"
        width={1000}
        height={460}
        projectionConfig={{ scale: 125 }}
        aria-label="World attack distribution. Use the zoom controls to adjust the view."
        style={{ width: "100%", height: "100%" }}
      >
        <ZoomableGroup
          zoom={position.zoom}
          center={position.coordinates}
          onMoveEnd={handleMoveEnd} // เปลี่ยนกลับมาใช้ onMoveEnd
          minZoom={1}
          maxZoom={8}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  tabIndex={-1}
                  aria-label={geo.properties.name}
                  fill="var(--map-land)"
                  stroke="var(--map-border)"
                  strokeWidth={0.75}
                  vectorEffect="non-scaling-stroke"
                  onMouseEnter={(e) => {
                    const { name } = geo.properties;
                    setTooltip({ show: true, content: name, x: e.clientX, y: e.clientY });
                  }}
                  onMouseMove={(e) => {
                    setTooltip((prev) => ({ ...prev, x: e.clientX, y: e.clientY }));
                  }}
                  onMouseLeave={() => {
                    setTooltip({ show: false, content: "", x: 0, y: 0 });
                  }}
                  style={{
                    default: { transition: "fill 150ms" },
                    hover: { fill: "var(--map-hover)", cursor: "crosshair" },
                    pressed: { fill: "var(--map-hover)" },
                  }}
                />
              ))
            }
          </Geographies>

          {markers.map(({ id, name, coordinates, status }, index) => {
            const isActive = activeMarkerId === id;
            const label = `${status === "failed" ? "Critical" : status === "running" ? "Active" : "Dormant"} · ${name} · ${id}`;
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
                  {status === "failed" ? <path d="M 0 -5 L 5 0 L 0 5 L -5 0 Z" fill="var(--danger)" stroke={isActive ? "var(--text)" : "var(--surface)"} strokeWidth={isActive ? 1.5 : 1} /> : status === "running" ? <circle r={isActive ? 5 : 4} fill="var(--info)" stroke={isActive ? "var(--text)" : "var(--surface)"} strokeWidth={isActive ? 1.5 : 1} /> : <rect x={-4} y={-4} width={8} height={8} fill="var(--neutral)" stroke={isActive ? "var(--text)" : "var(--surface)"} strokeWidth={isActive ? 1.5 : 1} />}
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

      <div className="pointer-events-none absolute bottom-4 left-4 max-w-[calc(100%-88px)] rounded-lg border border-border bg-surface px-3 py-2 text-xs text-text-muted" role={status === "error" ? "alert" : "status"}>
        {status === "loading" ? "Loading attack locations…" : status === "error" ? <span className="text-danger">Attack locations unavailable. Retrying automatically.</span> : status === "refreshing" || status === "stale" ? <RefreshStatus status={status} /> : markers.length === 0 ? "No attack locations in the last successful response." : "Drag to explore · scroll to zoom"}
      </div>
      <div className="absolute bottom-4 right-4 flex flex-col gap-2">
        <button onClick={handleZoomIn} disabled={position.zoom >= 8} aria-label="Zoom in" className="ui-button h-10 w-10 text-base">+</button>
        <button onClick={handleZoomOut} disabled={position.zoom <= 1} aria-label="Zoom out" className="ui-button h-10 w-10 text-base">−</button>
        <button onClick={handleReset} aria-label="Reset map view" className="ui-button h-10 w-10 p-0">
          <LocateFixed className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
