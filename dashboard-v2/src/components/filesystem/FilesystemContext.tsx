/* eslint-disable @typescript-eslint/no-explicit-any -- Transitional context bridge for the decomposed filesystem workspace. */
import { createContext, useContext } from "react";

// We omit 'isFullscreen' and other props that are specific to the layout instance

export interface FilesystemContextType extends Record<string, any> {
  expiredSessionId: string | null;
  allSessions: any[];
  setExpiredSessionId: (id: string | null) => void;
  handleUserSelectSession: (id: string, sessionObj?: any) => void;
  // Remaining workspace props are carried through the transitional record.
}


export const FilesystemContext = createContext<FilesystemContextType | null>(null);

export function useFilesystemContext() {
  const ctx = useContext(FilesystemContext);
  if (!ctx) {
    throw new Error("useFilesystemContext must be used within a FilesystemContext.Provider");
  }
  return ctx;
}
