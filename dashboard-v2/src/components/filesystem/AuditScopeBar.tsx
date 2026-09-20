/* eslint-disable @typescript-eslint/no-explicit-any */
import React from "react";
import { AuditSessionSelect } from "./AuditSessionSelect";
import { AuditFilterControls } from "./AuditFilterControls";

export interface AuditScopeBarProps {
  filteredActiveSessions: any[];
  filteredClosedSessions: any[];
  selectedSessionId: string | null;
  handleUserSelectSession: any;
  totalSessionsCount: number;
  hideHomeOnly: boolean;
  targetPathFilter: string | null;
  handleResetAuditFilters: () => void;
  allSessions: any[];
  directoryHasMore: boolean;
  directoryIsLoading: boolean;
  directoryIsComplete: boolean;
  loadMoreDirectory: () => void;
  auditSearchItems: any[];
  auditSearchHasMore: boolean;
  auditSearchIsLoading: boolean;
  auditSearchIsComplete: boolean;
  searchAuditSessions: (q: string) => void;
  loadMoreAuditSearch: () => void;
  clearAuditSearch: () => void;
  auditStatus: any;
  auditErrorMessage: any;
  retryInitialDirectory: () => void;
  handleToggleHideHomeOnly: () => void;
  handleSelectTargetPath: (path: string | null) => void;
  distinctPaths: any;
  homeOnlyCount: number;
  filteredSessionsCount: number;
  selectedPath: string | null;
}

export function AuditScopeBar(props: AuditScopeBarProps) {
  return (
    <div
      className="flex flex-col sm:flex-row sm:items-center gap-2.5 rounded-xl border border-border bg-surface px-3 py-2 shadow-xs"
      role="toolbar"
      aria-label="Audit session and replay toolbar"
    >
      <div
        className="flex flex-wrap items-center gap-2 min-w-0"
        role="group"
        aria-label="Audited session and filter controls"
      >
        <AuditSessionSelect
          sessions={props.filteredActiveSessions}
          recentClosedSessions={props.filteredClosedSessions}
          selectedSessionId={props.selectedSessionId}
          onSelectSession={props.handleUserSelectSession}
          totalCount={props.totalSessionsCount}
          hasActiveFilters={props.hideHomeOnly || props.targetPathFilter !== null}
          onResetFilters={props.handleResetAuditFilters}
          allSessionsList={props.allSessions}
          directoryHasMore={props.directoryHasMore}
          directoryIsLoading={props.directoryIsLoading}
          directoryIsComplete={props.directoryIsComplete}
          onLoadMoreDirectory={props.loadMoreDirectory}
          searchResults={props.auditSearchItems}
          searchHasMore={props.auditSearchHasMore}
          searchIsLoading={props.auditSearchIsLoading}
          searchIsComplete={props.auditSearchIsComplete}
          onSearch={(q) => void props.searchAuditSessions(q)}
          onLoadMoreSearch={props.loadMoreAuditSearch}
          onClearSearch={props.clearAuditSearch}
          hideHomeOnly={props.hideHomeOnly}
          targetPathFilter={props.targetPathFilter}
          status={props.auditStatus}
          errorMessage={props.auditErrorMessage}
          onRetry={props.retryInitialDirectory}
        />
        <div className="h-4 w-px bg-border hidden sm:block shrink-0" aria-hidden="true" />
        <AuditFilterControls
          hideHomeOnly={props.hideHomeOnly}
          onToggleHideHomeOnly={props.handleToggleHideHomeOnly}
          targetPath={props.targetPathFilter}
          onSelectTargetPath={props.handleSelectTargetPath}
          distinctPaths={props.distinctPaths}
          homeOnlyCount={props.homeOnlyCount}
          filteredCount={props.filteredSessionsCount}
          totalCount={props.totalSessionsCount}
          onResetFilters={props.handleResetAuditFilters}
          selectedCanvasPath={props.selectedPath}
        />
      </div>
    </div>
  );
}
