import type { FilesystemTopologyNode } from "@/lib/dashboardTypes";

import type { VerifiedCwdTransition } from "./filesystemTransitions";
import {
  DEFAULT_DENSITY_THRESHOLDS,
  type GraphNode,
} from "./filesystemUtils";

export type MinimapVisibilityPreference = "auto" | "show" | "hide";

export interface MinimapVisibilityInput {
  preference: MinimapVisibilityPreference;
  totalNodes: number;
  totalSources: number;
  currentZoom: number;
  fitZoom: number | null;
}

export type TransitionEndpointCoverageStatus = "visible" | "aggregated" | "unavailable";

export interface TransitionEndpointCoverage {
  path: string;
  status: TransitionEndpointCoverageStatus;
  aggregatePath: string | null;
}

export function topologyExceedsMinimapDensityThreshold(
  totalNodes: number,
  totalSources: number,
): boolean {
  return totalNodes > DEFAULT_DENSITY_THRESHOLDS.detailedMaxNodes ||
    totalSources > DEFAULT_DENSITY_THRESHOLDS.detailedMaxSources;
}

export function deriveMinimapVisibility(input: MinimapVisibilityInput): boolean {
  if (input.preference === "show") return true;
  if (input.preference === "hide") return false;

  if (topologyExceedsMinimapDensityThreshold(input.totalNodes, input.totalSources)) {
    return true;
  }

  if (
    input.fitZoom === null ||
    !Number.isFinite(input.fitZoom) ||
    !Number.isFinite(input.currentZoom)
  ) {
    return false;
  }

  return Math.abs(input.currentZoom - input.fitZoom) > 0.005;
}

/**
 * Returns only presentation-safe paths from the verified transition model.
 * Failed destinations cannot cross this boundary because their model exposes
 * `toPath: null`.
 */
export function requiredTransitionEndpointPaths(
  transition: VerifiedCwdTransition | null,
): string[] {
  if (!transition) return [];
  const candidates = transition.presentationKind === "directed"
    ? [transition.fromPath, transition.toPath]
    : [transition.markerPath];
  return [...new Set(candidates.filter((path): path is string => Boolean(path)))];
}

/**
 * Explains why a verified endpoint cannot be drawn. If density aggregation
 * owns the omission, the nearest visible ancestor is named explicitly.
 */
export function deriveTransitionEndpointCoverage(
  requiredPaths: readonly string[],
  allNodes: readonly FilesystemTopologyNode[],
  renderedNodes: readonly GraphNode[],
): TransitionEndpointCoverage[] {
  const allByPath = new Map(allNodes.map((node) => [node.path, node]));
  const renderedByPath = new Map(renderedNodes.map((node) => [node.path, node]));

  return requiredPaths.map((path) => {
    if (renderedByPath.has(path)) {
      return { path, status: "visible" as const, aggregatePath: null };
    }

    const node = allByPath.get(path);
    if (!node) {
      return { path, status: "unavailable" as const, aggregatePath: null };
    }

    let parentPath = node.parentPath;
    const visited = new Set<string>([path]);
    while (parentPath && !visited.has(parentPath)) {
      if (renderedByPath.has(parentPath)) {
        return { path, status: "aggregated" as const, aggregatePath: parentPath };
      }
      visited.add(parentPath);
      parentPath = allByPath.get(parentPath)?.parentPath ?? null;
    }

    return { path, status: "unavailable" as const, aggregatePath: null };
  });
}
