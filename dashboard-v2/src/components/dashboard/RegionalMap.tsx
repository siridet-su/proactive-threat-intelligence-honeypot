"use client";

import { useState } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const markers = [
  { name: "Node Alpha", coordinates: [-95.7129, 37.0902], status: "running" },
  { name: "Node Beta", coordinates: [5.2913, 52.1326], status: "completed" },
  { name: "Node Gamma", coordinates: [104.1954, 35.8617], status: "failed" },
  { name: "Node Delta", coordinates: [10.4515, 51.1657], status: "completed" },
];

export default function RegionalMap() {
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
  function handleMoveEnd(newPosition: any) {
    setPosition(newPosition);
  }

  return (
    // คง touchAction: "none" ไว้เพื่อป้องกันเบราว์เซอร์ซูมหน้าจอ
    <div className="w-full h-full relative bg-[#09090b] cursor-grab active:cursor-grabbing" style={{ touchAction: "none" }}>
      <ComposableMap 
        projection="geoMercator" 
        style={{ width: "100%", height: "100%", outline: "none" }}
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

          {markers.map(({ name, coordinates, status }) => (
            <Marker key={name} coordinates={coordinates as [number, number]}>
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

      <div className="absolute bottom-4 right-4 flex flex-col bg-[#111116] border border-slate-800 rounded-md overflow-hidden text-slate-400">
         <button onClick={handleZoomIn} className="px-3 py-1.5 hover:bg-slate-800 hover:text-white border-b border-slate-800 focus:outline-none">+</button>
         <button onClick={handleZoomOut} className="px-3 py-1.5 hover:bg-slate-800 hover:text-white focus:outline-none">-</button>
      </div>
    </div>
  );
}