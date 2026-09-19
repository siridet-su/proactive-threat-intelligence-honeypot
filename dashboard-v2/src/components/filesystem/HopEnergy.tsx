"use client";

import { motion, type Transition } from "framer-motion";
import type { CSSProperties } from "react";

import type { GraphElementBounds, GraphNode } from "./filesystemUtils";

interface HopEnergyProps {
  from?: GraphNode;
  to: GraphNode;
  fromBounds?: GraphElementBounds;
  toBounds?: GraphElementBounds;
  durationMs: number;
  reducedMotion: boolean;
  transition: Transition;
}

// Each event starts a shared repeating clock: one playback interval for travel
// and impact, then one for rest. Layout updates keep the current cycle in sync.
export function HopEnergy({
  from,
  to,
  fromBounds,
  toBounds,
  durationMs,
  reducedMotion,
  transition,
}: HopEnergyProps) {
  const moving = Boolean(from && from.path !== to.path);
  let route: string | null = null;

  if (from && moving) {
    const vertical = from.parentPath === to.path || to.parentPath === from.path || Math.abs(to.y - from.y) > 8;
    const direction = vertical ? Math.sign(to.y - from.y) || 1 : Math.sign(to.x - from.x) || 1;
    const startX = from.x + (vertical ? 0 : direction * (fromBounds?.width ?? 8) / 2);
    const startY = from.y + (vertical ? direction * (fromBounds?.height ?? 5) / 2 : 0);
    const endX = to.x - (vertical ? 0 : direction * (toBounds?.width ?? 12) / 2);
    const endY = to.y - (vertical ? direction * (toBounds?.height ?? 5) / 2 : 0);
    const bend = Math.min(25, Math.max(8, Math.abs(vertical ? endY - startY : endX - startX) * 0.5));
    route = vertical
      ? `M ${startX} ${startY} C ${startX} ${startY + direction * bend}, ${endX} ${endY - direction * bend}, ${endX} ${endY}`
      : `M ${startX} ${startY} C ${startX + direction * bend} ${startY}, ${endX - direction * bend} ${endY}, ${endX} ${endY}`;
  }

  return (
    <div
      className="pti-hop-energy pointer-events-none absolute inset-0"
      aria-hidden="true"
      style={{ "--hop-cycle-duration": `${durationMs}ms` } as CSSProperties}
    >
      {route && (
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 h-full w-full overflow-visible">
          <motion.path
            initial={false}
            animate={{ d: route }}
            transition={transition}
            className="pti-hop-route-glow"
          />
          <motion.path
            initial={false}
            animate={{ d: route }}
            transition={transition}
            className="pti-hop-route"
          />
          {!reducedMotion && ["bloom", "wake", "tail", "halo", "body", "core"].map((layer) => (
            <motion.path
              key={layer}
              initial={false}
              animate={{ d: route }}
              transition={transition}
              pathLength={100}
              className={`pti-hop-packet pti-hop-packet-${layer}`}
            />
          ))}
        </svg>
      )}
      {moving && !reducedMotion && (
        <motion.div
          initial={false}
          animate={{ left: `${to.x}%`, top: `${to.y}%`, width: `${toBounds?.width ?? 12}%`, height: `${toBounds?.height ?? 5}%` }}
          transition={transition}
          className="absolute -translate-x-1/2 -translate-y-1/2 rounded-lg"
        >
          <span className="pti-hop-wave" />
        </motion.div>
      )}
    </div>
  );
}
