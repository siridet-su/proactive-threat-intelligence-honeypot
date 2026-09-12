"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ChevronUp, Map } from "lucide-react";
import { useEffect, useState } from "react";
import type { GraphCallout, GraphNode, LabelPosition } from "./filesystemUtils";

interface TopologyMinimapProps {
  graphNodes: GraphNode[];
  graphNodeByPath: Map<string, GraphNode>;
  graphCallouts: GraphCallout[];
  selectedPath: string | null;
  selectedSessionId: string | null;
  minimapViewport: { x: number; y: number; width: number; height: number } | null;
  positionForCallout: (callout: GraphCallout, index: number) => LabelPosition;
  onFit: () => void;
}

export function TopologyMinimap({
  graphNodes,
  graphNodeByPath,
  graphCallouts,
  selectedPath,
  selectedSessionId,
  minimapViewport,
  positionForCallout,
  onFit,
}: TopologyMinimapProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    const timer = setTimeout(() => {
      if (typeof window !== "undefined") {
        try {
          const saved = localStorage.getItem("pti-topology-minimap-collapsed-v1");
          if (saved === "true") setIsCollapsed(true);
        } catch {
          // ignore
        }
      }
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const handleToggleCollapse = (collapsed: boolean) => {
    setIsCollapsed(collapsed);
    if (typeof window !== "undefined") {
      try {
        localStorage.setItem("pti-topology-minimap-collapsed-v1", String(collapsed));
      } catch {
        // ignore
      }
    }
  };

  const calloutPositions = graphCallouts.map((callout, index) => ({
    callout,
    position: positionForCallout(callout, index),
  }));

  // Stable world bounds based on canvas plane coordinates (0-100) and any dragged nodes/callouts.
  // Minimap viewport is excluded from the world bounds so the map remains stable when camera pans.
  const horizontalCoordinates = [
    0,
    100,
    ...graphNodes.map((node) => node.x),
    ...calloutPositions.map(({ position }) => position.x),
  ];
  const verticalCoordinates = [
    0,
    100,
    ...graphNodes.map((node) => node.y),
    ...calloutPositions.map(({ position }) => position.y),
  ];
  const worldMinX = Math.min(...horizontalCoordinates);
  const worldMaxX = Math.max(...horizontalCoordinates);
  const worldMinY = Math.min(...verticalCoordinates);
  const worldMaxY = Math.max(...verticalCoordinates);

  // SVG viewBox is 0 0 100 64 (matches aspect ratio of the 860x500 plane).
  const PADDING_X = 6;
  const PADDING_Y = 5;
  const INNER_WIDTH = 100 - PADDING_X * 2; // 88
  const INNER_HEIGHT = 64 - PADDING_Y * 2; // 54

  const spanX = Math.max(1, worldMaxX - worldMinX);
  const spanY = Math.max(1, worldMaxY - worldMinY);

  const normalizeX = (value: number) => PADDING_X + ((value - worldMinX) / spanX) * INNER_WIDTH;
  const normalizeY = (value: number) => PADDING_Y + ((value - worldMinY) / spanY) * INNER_HEIGHT;

  // Viewfinder camera viewport coordinates clamped safely inside the 100x64 SVG box
  const viewfinder = minimapViewport
    ? (() => {
        const rawLeft = normalizeX(minimapViewport.x);
        const rawRight = normalizeX(minimapViewport.x + minimapViewport.width);
        const rawTop = normalizeY(minimapViewport.y);
        const rawBottom = normalizeY(minimapViewport.y + minimapViewport.height);

        const vLeft = Math.max(1.5, Math.min(98.5, rawLeft));
        const vRight = Math.max(1.5, Math.min(98.5, rawRight));
        const vTop = Math.max(1.5, Math.min(62.5, rawTop));
        const vBottom = Math.max(1.5, Math.min(62.5, rawBottom));

        return {
          x: vLeft,
          y: vTop,
          width: Math.max(3, vRight - vLeft),
          height: Math.max(3, vBottom - vTop),
        };
      })()
    : null;

  return (
    <div
      className="absolute bottom-3 right-5 z-20 hidden w-28 overflow-hidden rounded-xl border border-border/80 bg-surface/85 backdrop-blur-md p-1.5 text-left shadow-md transition-all duration-200 hover:border-border hover:bg-surface/95 sm:block select-none"
    >
      <div>
        <button
          type="button"
          onClick={() => handleToggleCollapse(!isCollapsed)}
          className="group flex w-full items-center justify-between rounded px-1 py-0.5 text-text-subtle transition-colors hover:bg-surface-hover hover:text-text focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus-ring"
          title={isCollapsed ? "Expand topology minimap overview" : "Minimize topology minimap overview"}
          aria-label={isCollapsed ? "Expand topology minimap overview" : "Minimize topology minimap overview"}
          aria-expanded={!isCollapsed}
        >
          <div className="flex items-center gap-1.5">
            <Map className="h-3 w-3 text-primary" aria-hidden="true" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em]">Overview</span>
          </div>
          <motion.span
            animate={{ rotate: isCollapsed ? 0 : 180 }}
            transition={reducedMotion ? { duration: 0 } : { duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="inline-flex items-center text-text-subtle group-hover:text-text transition-colors"
          >
            <ChevronUp className="h-3 w-3" aria-hidden="true" />
          </motion.span>
        </button>
      </div>

      <AnimatePresence initial={false}>
        {!isCollapsed && (
          <motion.div
            key="minimap-content"
            initial={reducedMotion ? false : { height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={reducedMotion ? undefined : { height: 0, opacity: 0 }}
            transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="pt-1">
              <button
                type="button"
                onClick={onFit}
                className="group relative block w-full rounded border border-border/60 bg-surface-subtle/50 transition-colors hover:border-primary/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                title="Click minimap to reset / fit view"
                aria-label="Click minimap to reset / fit view"
              >
                <svg viewBox="0 0 100 64" preserveAspectRatio="none" className="h-16 w-full" aria-hidden="true">
                  {/* Camera Viewfinder lens framing the current screen area */}
                  {viewfinder && (
                    <rect
                      x={viewfinder.x}
                      y={viewfinder.y}
                      width={viewfinder.width}
                      height={viewfinder.height}
                      rx="2"
                      fill="var(--text)"
                      fillOpacity="0.06"
                      stroke="var(--text-subtle)"
                      strokeOpacity="0.65"
                      strokeWidth="1"
                      className="transition-all duration-150"
                    />
                  )}

                  {/* Directory Tree Hierarchy Edges */}
                  {graphNodes.map((node) => {
                    const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                    if (!parent) return null;
                    const isSelectedBranch = node.path === selectedPath;
                    return (
                      <path
                        key={`minimap-${parent.path}-${node.path}`}
                        d={`M ${normalizeX(parent.x)} ${normalizeY(parent.y)} C ${normalizeX(parent.x)} ${normalizeY((parent.y + node.y) / 2)}, ${normalizeX(node.x)} ${normalizeY((parent.y + node.y) / 2)}, ${normalizeX(node.x)} ${normalizeY(node.y)}`}
                        fill="none"
                        stroke={isSelectedBranch ? "var(--primary)" : "var(--border-strong)"}
                        strokeWidth={isSelectedBranch ? "1" : "0.7"}
                        strokeOpacity={isSelectedBranch ? 0.95 : 0.45}
                      />
                    );
                  })}

                  {/* Callout Leader Lines (Directory Node to Attacker IP) */}
                  {calloutPositions.map(({ callout, position }) => {
                    const targetNode = graphNodeByPath.get(callout.path);
                    if (!targetNode) return null;
                    const isSelectedSession = callout.sessionIds.includes(selectedSessionId ?? "");
                    const startX = normalizeX(targetNode.x);
                    const startY = normalizeY(targetNode.y);
                    const endX = normalizeX(position.x);
                    const endY = normalizeY(position.y);
                    const midX = (startX + endX) / 2;
                    return (
                      <path
                        key={`minimap-leader-${callout.sourceIp}`}
                        d={`M ${startX} ${startY} C ${midX} ${startY}, ${midX} ${endY}, ${endX} ${endY}`}
                        fill="none"
                        stroke={isSelectedSession ? "var(--primary)" : "var(--border-strong)"}
                        strokeWidth={isSelectedSession ? "1" : "0.6"}
                        strokeDasharray={isSelectedSession ? undefined : "1.5 1.5"}
                        strokeOpacity={isSelectedSession ? 0.95 : 0.45}
                      />
                    );
                  })}

                  {/* Directory Nodes */}
                  {graphNodes.map((node) => {
                    const isSelected = node.path === selectedPath;
                    const cx = normalizeX(node.x);
                    const cy = normalizeY(node.y);
                    return (
                      <g key={`minimap-node-${node.path}`}>
                        {isSelected && (
                          <circle
                            cx={cx}
                            cy={cy}
                            r="3.6"
                            fill="var(--primary)"
                            fillOpacity="0.28"
                          />
                        )}
                        <circle
                          cx={cx}
                          cy={cy}
                          r={isSelected ? "2.1" : "1.4"}
                          fill={isSelected ? "var(--primary)" : "var(--text-subtle)"}
                        />
                      </g>
                    );
                  })}

                  {/* Attacker IP Callout Dots */}
                  {calloutPositions.map(({ callout, position }) => {
                    const isSelected = callout.sessionIds.includes(selectedSessionId ?? "");
                    const cx = normalizeX(position.x);
                    const cy = normalizeY(position.y);
                    return (
                      <g key={`minimap-callout-${callout.sourceIp}`}>
                        {isSelected && (
                          <circle
                            cx={cx}
                            cy={cy}
                            r="4.2"
                            fill="var(--primary)"
                            fillOpacity="0.32"
                          />
                        )}
                        <circle
                          cx={cx}
                          cy={cy}
                          r={isSelected ? "2.3" : "1.6"}
                          fill={isSelected ? "var(--primary)" : "var(--success)"}
                        />
                      </g>
                    );
                  })}
                </svg>
                <span className="sr-only">Fit topology in view</span>
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
