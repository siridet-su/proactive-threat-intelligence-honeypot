"use client";

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
  const calloutPositions = graphCallouts.map((callout, index) => ({
    callout,
    position: positionForCallout(callout, index),
  }));
  const horizontalCoordinates = [
    0,
    100,
    ...graphNodes.map((node) => node.x),
    ...calloutPositions.map(({ position }) => position.x),
    ...(minimapViewport ? [minimapViewport.x, minimapViewport.x + minimapViewport.width] : []),
  ];
  const verticalCoordinates = [
    0,
    100,
    ...graphNodes.map((node) => node.y),
    ...calloutPositions.map(({ position }) => position.y),
    ...(minimapViewport ? [minimapViewport.y, minimapViewport.y + minimapViewport.height] : []),
  ];
  const minX = Math.min(...horizontalCoordinates);
  const maxX = Math.max(...horizontalCoordinates);
  const minY = Math.min(...verticalCoordinates);
  const maxY = Math.max(...verticalCoordinates);
  const normalizeX = (value: number) => ((value - minX) / Math.max(1, maxX - minX)) * 100;
  const normalizeY = (value: number) => ((value - minY) / Math.max(1, maxY - minY)) * 100;

  return (
    <button
      type="button"
      className="absolute bottom-3 right-5 z-20 hidden w-28 overflow-hidden rounded-lg border border-border bg-surface p-1.5 text-left shadow-sm transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2 focus-visible:ring-offset-surface sm:block"
      onClick={onFit}
      aria-label="Fit topology in view"
      title="Fit topology in view"
    >
      <span className="mb-1 block px-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-text-subtle">Overview</span>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-16 w-full rounded border border-border bg-surface-subtle" aria-hidden="true">
        {graphNodes.map((node) => {
          const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
          return parent ? (
            <path
              key={`minimap-${parent.path}-${node.path}`}
              d={`M ${normalizeX(parent.x)} ${normalizeY(parent.y)} C ${normalizeX(parent.x)} ${normalizeY((parent.y + node.y) / 2)}, ${normalizeX(node.x)} ${normalizeY((parent.y + node.y) / 2)}, ${normalizeX(node.x)} ${normalizeY(node.y)}`}
              fill="none"
              stroke="var(--border-strong)"
              strokeWidth="0.8"
            />
          ) : null;
        })}
        {graphNodes.map((node) => (
          <circle
            key={`minimap-node-${node.path}`}
            cx={normalizeX(node.x)}
            cy={normalizeY(node.y)}
            r="1.6"
            fill={node.path === selectedPath ? "var(--primary)" : "var(--text-subtle)"}
          />
        ))}
        {calloutPositions.map(({ callout, position }) => {
          const selected = callout.sessionIds.includes(selectedSessionId ?? "");
          return (
            <circle
              key={`minimap-callout-${callout.sourceIp}`}
              cx={normalizeX(position.x)}
              cy={normalizeY(position.y)}
              r="2"
              fill={selected ? "var(--primary)" : "var(--success)"}
            />
          );
        })}
        {minimapViewport && (
          <rect
            x={normalizeX(minimapViewport.x)}
            y={normalizeY(minimapViewport.y)}
            width={Math.max(2, normalizeX(minimapViewport.x + minimapViewport.width) - normalizeX(minimapViewport.x))}
            height={Math.max(2, normalizeY(minimapViewport.y + minimapViewport.height) - normalizeY(minimapViewport.y))}
            rx="1.5"
            fill="none"
            stroke="var(--primary)"
            strokeWidth="1.4"
          />
        )}
      </svg>
      <span className="sr-only">Fit topology in view</span>
    </button>
  );
}
