"use client";

import { useState, useEffect } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";

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

export default function RegionalMap() {
  const [markers, setMarkers] = useState<MapMarker[]>([]);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            const newMarkers = data.filter(isDashboardThreatEvent).map((threat) => ({
              id: threat.id,
              name: ` () - `,
              coordinates: [threat.geo.lon, threat.geo.lat] as [number, number],
              status: threat.severity === "Critical" || threat.severity === "High" ? "failed" as const : "running" as const
            })).filter((marker) => marker.coordinates[0] !== 0 && marker.coordinates[1] !== 0);
            setMarkers(newMarkers);
          }
        }
      } catch (err) {
        console.error("Failed to fetch threats for map:", err);
      }
    };
    
    fetchThreats();
    const interval = setInterval(fetchThreats, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);
  const [position, setPosition] = useState({ coordinates: [0, 20] as [number, number], zoom: 1 });
  const [tooltip, setTooltip] = useState({ show: false, content: "", x: 0, y: 0 });

  function handleZoomIn() {
    if (position.zoom >= 8) return;
    setPosition((pos) => ({ ...pos, zoom: pos.zoom * 1.5 }));
  }

  function handleZoomOut() {
    if (position.zoom <= 1) return;
    setPosition((pos) => ({ ...pos, zoom: pos.zoom / 1.5 }));
  }

  // ใช้ onMoveEnd แทน onMove เพื่อให้ Trackpad สามารถซูมและเลื่อนได้ลื่นไหล
  function handleMoveEnd(newPosition: MapPosition) {
    setPosition(newPosition);
  }

  return (
    <div className="w-full h-full relative bg-[#09090b] cursor-grab active:cursor-grabbing" style={{ touchAction: "none" }}>
      <ComposableMap 
        projection="geoMercator" 
        style={{ width: "100%", height: "100%", outline: "none" }}
      >
        <ZoomableGroup 
          zoom={position.zoom} 
          center={position.coordinates} 
          onMoveEnd={handleMoveEnd}
          minZoom={1} 
          maxZoom={8}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#16161d"
                  stroke="#27272a"
                  strokeWidth={0.5}
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
                    default: { outline: "none", transition: "fill 0.2s" },
                    hover: { fill: "#27272a", outline: "none", cursor: "crosshair" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>

          {markers.map(({ id, name, coordinates, status }, index) => (
            <Marker key={id || index} coordinates={coordinates}>
            <circle r={4} fill={
              status === "running" ? "#34d399" : 
              status === "failed" ? "#f87171" : "#a855f7"
            } />
            {status === "running" && (
              <circle r={8} fill="#34d399" opacity={0.4} className="animate-ping" />
            )}
            </Marker>
          ))}
        </ZoomableGroup>
      </ComposableMap>
      
      {tooltip.show && (
        <div 
          className="fixed z-50 px-3 py-1.5 bg-[#111116] border border-slate-700 text-slate-200 text-xs rounded-md shadow-[0_0_15px_rgba(0,0,0,0.5)] font-sans pointer-events-none transform -translate-x-1/2 -translate-y-[150%]"
          style={{ top: tooltip.y, left: tooltip.x }}
        >
          {tooltip.content}
        </div>
      )}

      {!markers.length && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="bg-[#111116]/90 border border-slate-800 rounded-md px-4 py-3 text-center">
            <p className="text-[11px] text-slate-300">No verified public coordinates</p>
            <p className="text-[10px] text-slate-500 mt-1">The API returned no map-safe geolocation for this window.</p>
          </div>
        </div>
      )}

      <div className="absolute bottom-4 right-4 flex flex-col bg-[#111116] border border-slate-800 rounded-md overflow-hidden text-slate-400">
         <button onClick={handleZoomIn} className="px-3 py-1.5 hover:bg-slate-800 hover:text-white border-b border-slate-800 focus:outline-none">+</button>
         <button onClick={handleZoomOut} className="px-3 py-1.5 hover:bg-slate-800 hover:text-white focus:outline-none">-</button>
      </div>
    </div>
  );
}
