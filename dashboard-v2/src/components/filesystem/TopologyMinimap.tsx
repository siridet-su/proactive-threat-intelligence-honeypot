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
              d={`M ${parent.x} ${parent.y} C ${parent.x} ${(parent.y + node.y) / 2}, ${node.x} ${(parent.y + node.y) / 2}, ${node.x} ${node.y}`}
              fill="none"
              stroke="var(--border-strong)"
              strokeWidth="0.8"
            />
          ) : null;
        })}
        {graphNodes.map((node) => (
          <circle
            key={`minimap-node-${node.path}`}
            cx={node.x}
            cy={node.y}
            r="1.6"
            fill={node.path === selectedPath ? "var(--primary)" : "var(--text-subtle)"}
          />
        ))}
        {graphCallouts.map((callout, index) => {
          const position = positionForCallout(callout, index);
          const selected = callout.sessionIds.includes(selectedSessionId ?? "");
          return (
            <circle
              key={`minimap-callout-${callout.sourceIp}`}
              cx={Math.min(98, Math.max(2, position.x))}
              cy={Math.min(98, Math.max(2, position.y))}
              r="2"
              fill={selected ? "var(--primary)" : "var(--success)"}
            />
          );
        })}
        {minimapViewport && (
          <rect
            x={minimapViewport.x}
            y={minimapViewport.y}
            width={minimapViewport.width}
            height={minimapViewport.height}
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
