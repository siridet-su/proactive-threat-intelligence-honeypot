"use client";

import { motion, type Transition } from "framer-motion";
import { AlertTriangle, CornerDownRight, Route } from "lucide-react";
import { useId, useMemo, type CSSProperties } from "react";

import type { VerifiedCwdTransition } from "./filesystemTransitions";
import type { GraphElementBounds, GraphNode } from "./filesystemUtils";

export type TransitionOverlayState = "previous" | "current" | "future";

export interface TransitionOverlayItem {
  transition: VerifiedCwdTransition;
  state: TransitionOverlayState;
  isAnchored: boolean;
}

export interface TransitionOverlayProps {
  transitions: readonly VerifiedCwdTransition[];
  currentTransition: VerifiedCwdTransition | null;
  nodes: readonly GraphNode[];
  nodeBounds?: Readonly<Record<string, GraphElementBounds>>;
  durationMs: number;
  reducedMotion: boolean;
  layoutTransition?: Transition;
  showLegend?: boolean;
}

interface OverlayGeometry {
  route: string;
  labelX: number;
  labelY: number;
  targetX: number;
  targetY: number;
  selfLoop: boolean;
}

function isSafeHop(value: number | null): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/**
 * Preserves the displayed chronological sequence and only adds an anchored
 * current event when it lives outside the loaded history window.
 */
export function deriveTransitionOverlayItems(
  transitions: readonly VerifiedCwdTransition[],
  currentTransition: VerifiedCwdTransition | null,
): TransitionOverlayItem[] {
  const currentIndex = currentTransition
    ? transitions.findIndex((transition) => transition.eventId === currentTransition.eventId)
    : -1;

  const displayed = transitions.map((transition, index): TransitionOverlayItem => {
    let state: TransitionOverlayState = "previous";
    if (currentIndex >= 0) {
      state = index < currentIndex ? "previous" : index === currentIndex ? "current" : "future";
    } else if (
      currentTransition &&
      isSafeHop(transition.absoluteHop) &&
      isSafeHop(currentTransition.absoluteHop)
    ) {
      state = transition.absoluteHop < currentTransition.absoluteHop ? "previous" : "future";
    }
    return { transition, state, isAnchored: false };
  });

  if (!currentTransition || currentIndex >= 0) return displayed;
  return [...displayed, { transition: currentTransition, state: "current", isAnchored: true }];
}

function markerPoint(
  path: string | null,
  nodeByPath: ReadonlyMap<string, GraphNode>,
): { x: number; y: number } | null {
  if (!path) return null;
  const node = nodeByPath.get(path);
  return node ? { x: node.x, y: node.y } : null;
}

function directedGeometry(
  transition: VerifiedCwdTransition,
  nodeByPath: ReadonlyMap<string, GraphNode>,
  nodeBounds: Readonly<Record<string, GraphElementBounds>>,
  lane: number,
): OverlayGeometry | null {
  if (!transition.fromPath || !transition.toPath) return null;
  const from = nodeByPath.get(transition.fromPath);
  const to = nodeByPath.get(transition.toPath);
  if (!from || !to) return null;

  if (from.path === to.path) {
    const bounds = nodeBounds[from.path];
    const halfWidth = Math.max(4, (bounds?.width ?? 10) / 2);
    const halfHeight = Math.max(2.5, (bounds?.height ?? 5) / 2);
    const radiusX = halfWidth + 3 + lane * 1.5;
    const radiusY = halfHeight + 3 + lane;
    const startX = from.x + halfWidth * 0.65;
    const startY = from.y - halfHeight * 0.8;
    const endX = from.x - halfWidth * 0.65;
    const endY = startY;
    return {
      route: `M ${startX} ${startY} C ${from.x + radiusX} ${from.y - radiusY}, ${from.x - radiusX} ${from.y - radiusY}, ${endX} ${endY}`,
      labelX: from.x,
      labelY: from.y - radiusY - 1.5,
      targetX: endX,
      targetY: endY,
      selfLoop: true,
    };
  }

  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const distance = Math.max(1, Math.hypot(dx, dy));
  const perpendicularX = -dy / distance;
  const perpendicularY = dx / distance;
  const laneOffset = 2 + lane * 3;
  const controlX = (from.x + to.x) / 2 + perpendicularX * laneOffset;
  const controlY = (from.y + to.y) / 2 + perpendicularY * laneOffset;
  const fromBounds = nodeBounds[from.path];
  const toBounds = nodeBounds[to.path];
  const trimStart = Math.min(distance * 0.18, Math.max(2, ((fromBounds?.width ?? 8) + (fromBounds?.height ?? 5)) / 4));
  const trimEnd = Math.min(distance * 0.18, Math.max(2, ((toBounds?.width ?? 8) + (toBounds?.height ?? 5)) / 4));
  const unitX = dx / distance;
  const unitY = dy / distance;
  const startX = from.x + unitX * trimStart;
  const startY = from.y + unitY * trimStart;
  const endX = to.x - unitX * trimEnd;
  const endY = to.y - unitY * trimEnd;

  return {
    route: `M ${startX} ${startY} Q ${controlX} ${controlY}, ${endX} ${endY}`,
    labelX: (startX + 2 * controlX + endX) / 4,
    labelY: (startY + 2 * controlY + endY) / 4,
    targetX: endX,
    targetY: endY,
    selfLoop: false,
  };
}

function stateStyle(state: TransitionOverlayState) {
  if (state === "current") {
    return { color: "var(--primary)", opacity: 1, width: 0.72 };
  }
  if (state === "future") {
    return { color: "var(--border-strong)", opacity: 0.34, width: 0.34 };
  }
  return { color: "var(--primary)", opacity: 0.5, width: 0.38 };
}

function hopLabel(transition: VerifiedCwdTransition): string {
  return isSafeHop(transition.absoluteHop) ? `Hop ${transition.absoluteHop}` : "Hop unavailable";
}

function describeTransition(item: TransitionOverlayItem): string {
  const { transition, state } = item;
  const prefix = `${hopLabel(transition)}: ${state}`;
  if (transition.presentationKind === "directed") {
    return `${prefix} transition from ${transition.fromPath} to ${transition.toPath}`;
  }
  if (transition.presentationKind === "entry") {
    return `${prefix} entry at ${transition.markerPath}`;
  }
  if (transition.presentationKind === "failed-origin") {
    const origin = transition.markerPath ?? "an unavailable verified origin";
    return `${prefix} failed change at origin ${origin}; destination unavailable or unverified`;
  }
  return `${prefix} transition; verified endpoints unavailable`;
}

export function TransitionLegend() {
  return (
    <aside
      aria-label="Topology and transition legend"
      className="pointer-events-none absolute bottom-3 left-3 z-50 flex max-w-[calc(100%-1.5rem)] flex-wrap gap-x-3 gap-y-1 rounded-lg border border-border bg-surface/95 px-3 py-2 text-xs text-text-muted shadow-sm backdrop-blur-sm"
    >
      <span className="inline-flex items-center gap-1.5"><span className="h-px w-5 bg-border-strong" aria-hidden="true" />Filesystem hierarchy</span>
      <span className="inline-flex items-center gap-1.5"><span className="h-0.5 w-5 bg-primary/50" aria-hidden="true" />Previous transition</span>
      <span className="inline-flex items-center gap-1.5 font-semibold text-text"><span className="h-0.5 w-5 bg-primary" aria-hidden="true" />Current transition</span>
      <span className="inline-flex items-center gap-1.5"><span className="h-px w-5 bg-border-strong/40" aria-hidden="true" />Future transition</span>
      <span className="inline-flex items-center gap-1.5"><CornerDownRight className="h-3.5 w-3.5 text-primary" aria-hidden="true" />Entry marker</span>
      <span className="inline-flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5 text-warning" aria-hidden="true" />Failed at origin</span>
    </aside>
  );
}

export function TransitionOverlay({
  transitions,
  currentTransition,
  nodes,
  nodeBounds = {},
  durationMs,
  reducedMotion,
  layoutTransition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] },
  showLegend = true,
}: TransitionOverlayProps) {
  const markerNamespace = useId().replace(/:/g, "");
  const items = useMemo(
    () => deriveTransitionOverlayItems(transitions, currentTransition),
    [currentTransition, transitions],
  );
  const nodeByPath = useMemo(() => new Map(nodes.map((node) => [node.path, node])), [nodes]);
  const laneByEvent = useMemo(() => {
    const counts = new Map<string, number>();
    const lanes = new Map<string, number>();
    for (const item of items) {
      const transition = item.transition;
      if (transition.presentationKind !== "directed" || !transition.fromPath || !transition.toPath) continue;
      const key = `${transition.fromPath}\u0000${transition.toPath}`;
      const lane = counts.get(key) ?? 0;
      lanes.set(transition.eventId, lane);
      counts.set(key, lane + 1);
    }
    return lanes;
  }, [items]);

  const rendered = items.map((item) => {
    const transition = item.transition;
    const geometry = transition.presentationKind === "directed"
      ? directedGeometry(transition, nodeByPath, nodeBounds, laneByEvent.get(transition.eventId) ?? 0)
      : null;
    const marker = transition.presentationKind === "entry" || transition.presentationKind === "failed-origin"
      ? markerPoint(transition.markerPath, nodeByPath)
      : null;
    return { item, geometry, marker };
  });
  const hasAnchoredCurrent = items.some((item) => item.isAnchored && item.state === "current");

  return (
    <>
      <div className="pti-transition-overlay pointer-events-none absolute inset-0 z-[5]" data-testid="verified-transition-overlay">
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 h-full w-full overflow-visible" aria-hidden="true">
          <defs>
            {(["previous", "current", "future"] as const).map((state) => {
              const style = stateStyle(state);
              return (
                <marker
                  key={state}
                  id={`${markerNamespace}-${state}-transition-arrow`}
                  markerWidth="5"
                  markerHeight="5"
                  refX="4.2"
                  refY="2.5"
                  orient="auto"
                >
                  <polygon points="0 0, 5 2.5, 0 5" fill={style.color} opacity={style.opacity} />
                </marker>
              );
            })}
          </defs>

          {rendered.map(({ item, geometry, marker }, index) => {
            const { transition, state } = item;
            const style = stateStyle(state);
            const key = `${transition.eventId}:${index}`;
            if (geometry) {
              return (
                <g key={key}>
                  {state === "current" && (
                    <motion.path
                      initial={false}
                      animate={{ d: geometry.route }}
                      transition={reducedMotion ? { duration: 0 } : layoutTransition}
                      fill="none"
                      stroke="var(--primary)"
                      strokeOpacity="0.16"
                      strokeWidth="2"
                    />
                  )}
                  <motion.path
                    initial={false}
                    animate={{ d: geometry.route }}
                    transition={reducedMotion ? { duration: 0 } : layoutTransition}
                    fill="none"
                    stroke={style.color}
                    strokeOpacity={style.opacity}
                    strokeWidth={style.width}
                    strokeLinecap="round"
                    markerEnd={`url(#${markerNamespace}-${state}-transition-arrow)`}
                    data-transition-event-id={transition.eventId}
                    data-transition-kind="directed"
                    data-transition-state={state}
                    data-transition-route={`${transition.fromPath}→${transition.toPath}`}
                    data-transition-self-loop={geometry.selfLoop ? "true" : undefined}
                    data-anchored-transition={item.isAnchored ? "true" : undefined}
                  />
                  {state === "current" && (
                    <circle
                      data-testid="current-transition-indicator"
                      cx={geometry.targetX}
                      cy={geometry.targetY}
                      r="1.05"
                      fill="var(--surface)"
                      stroke="var(--primary)"
                      strokeWidth="0.55"
                    />
                  )}
                  {state === "current" && !reducedMotion && (
                    <>
                      <circle data-testid="transition-travel-packet" r="0.72" fill="var(--primary)">
                        <animateMotion dur={`${Math.max(300, durationMs)}ms`} repeatCount="indefinite" path={geometry.route} />
                      </circle>
                      <circle
                        data-testid="transition-current-pulse"
                        cx={geometry.targetX}
                        cy={geometry.targetY}
                        r="1.05"
                        fill="none"
                        stroke="var(--primary)"
                        strokeWidth="0.35"
                      >
                        <animate attributeName="r" values="1.05;2.5;1.05" dur={`${Math.max(600, durationMs)}ms`} repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.8;0;0.8" dur={`${Math.max(600, durationMs)}ms`} repeatCount="indefinite" />
                      </circle>
                    </>
                  )}
                </g>
              );
            }

            if (!marker) return null;
            const isFailed = transition.presentationKind === "failed-origin";
            return (
              <g
                key={key}
                transform={`translate(${marker.x} ${marker.y})`}
                data-transition-event-id={transition.eventId}
                data-transition-kind={transition.presentationKind}
                data-transition-state={state}
                data-transition-marker-path={transition.markerPath ?? undefined}
                data-anchored-transition={item.isAnchored ? "true" : undefined}
              >
                <circle
                  r={state === "current" ? "2.05" : "1.6"}
                  fill="var(--surface)"
                  stroke={isFailed ? "var(--warning)" : style.color}
                  strokeWidth={state === "current" ? "0.65" : "0.4"}
                  strokeOpacity={state === "current" ? 1 : style.opacity}
                />
                {isFailed ? (
                  <path d="M 0 -1.1 L 1.05 0.85 L -1.05 0.85 Z" fill="var(--warning)" />
                ) : (
                  <path d="M -0.75 -0.85 L 0.8 0 L -0.75 0.85 Z" fill={style.color} opacity={style.opacity} />
                )}
                {state === "current" && (
                  <circle data-testid="current-transition-indicator" r="2.6" fill="none" stroke={isFailed ? "var(--warning)" : "var(--primary)"} strokeWidth="0.35" />
                )}
                {state === "current" && !reducedMotion && (
                  <circle data-testid="transition-current-pulse" r="2.1" fill="none" stroke={isFailed ? "var(--warning)" : "var(--primary)"} strokeWidth="0.35">
                    <animate attributeName="r" values="2.1;3.7;2.1" dur={`${Math.max(600, durationMs)}ms`} repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.8;0;0.8" dur={`${Math.max(600, durationMs)}ms`} repeatCount="indefinite" />
                  </circle>
                )}
              </g>
            );
          })}
        </svg>

        {rendered.map(({ item, geometry, marker }, index) => {
          const point = geometry ? { x: geometry.labelX, y: geometry.labelY } : marker;
          if (!point) return null;
          const isCurrent = item.state === "current";
          const isFailed = item.transition.presentationKind === "failed-origin";
          return (
            <span
              key={`label:${item.transition.eventId}:${index}`}
              data-transition-hop-label="true"
              data-transition-event-id={item.transition.eventId}
              data-transition-state={item.state}
              className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 rounded border px-1 py-0.5 font-mono text-xs font-bold shadow-xs ${
                isFailed
                  ? "border-warning-border bg-warning-subtle text-warning"
                  : isCurrent
                    ? "border-primary bg-primary text-surface"
                    : item.state === "previous"
                      ? "border-primary/30 bg-surface/95 text-primary"
                      : "border-border bg-surface/90 text-text-subtle"
              }`}
              style={{ left: `${point.x}%`, top: `${point.y}%` } as CSSProperties}
            >
              {isFailed && <AlertTriangle className="mr-0.5 inline h-2.5 w-2.5" aria-hidden="true" />}
              {!isFailed && isCurrent && <Route className="mr-0.5 inline h-2.5 w-2.5" aria-hidden="true" />}
              {isSafeHop(item.transition.absoluteHop) ? item.transition.absoluteHop : "?"}
            </span>
          );
        })}
        {hasAnchoredCurrent && (
          <span
            data-testid="transition-unloaded-gap"
            data-gap-rendering="explicit-not-inferred"
            className="absolute right-3 top-3 z-20 rounded border border-dashed border-border-strong bg-surface/95 px-2 py-1 text-xs font-medium text-text-muted shadow-xs"
          >
            Unloaded history gap · no intermediate transitions inferred
          </span>
        )}
      </div>

      <ol aria-label="Verified CWD transition sequence" className="sr-only">
        {items.map((item, index) => <li key={`${item.transition.eventId}:${index}`}>{describeTransition(item)}</li>)}
      </ol>
      {showLegend && <TransitionLegend />}
    </>
  );
}
