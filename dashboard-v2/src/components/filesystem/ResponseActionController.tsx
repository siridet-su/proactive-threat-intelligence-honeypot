"use client";

import type { FilesystemTopologySession } from "@/lib/dashboardTypes";
import { useResponseAction, type UseResponseActionReturn } from "./useResponseAction";

export interface UseResponseActionControllerOptions {
  selectedSession: FilesystemTopologySession | null;
  sessionIsLive: boolean;
  enabled: boolean;
}

/**
 * Explicit response lifecycle owner for the filesystem feature. The page mounts
 * this controller once; ResponseActionPanel only receives its view model.
 */
export function useResponseActionController(
  options: UseResponseActionControllerOptions,
): UseResponseActionReturn {
  return useResponseAction(options);
}
