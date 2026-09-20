const fs = require('fs');

const path = './dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx';
let code = fs.readFileSync(path, 'utf8');

// 1. Add useState, AuditScopeBar imports
code = code.replace(/import React from "react";/, 'import React, { useState } from "react";\nimport { AuditScopeBar } from "./AuditScopeBar";');

// 2. Add the missing props to AuditFilesystemWorkspaceProps
const propsToAdd = `
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
`;
code = code.replace(/export interface AuditFilesystemWorkspaceProps \{/, "export interface AuditFilesystemWorkspaceProps {" + propsToAdd);

// 3. Update AuditFilesystemWorkspace function body
const funcHeader = `export function AuditFilesystemWorkspace(props: AuditFilesystemWorkspaceProps) {
  const [mobileTab, setMobileTab] = useState<"map" | "timeline">("map");

  return (
    <div className="flex flex-col h-full w-full">
      <div className="flex lg:hidden gap-2 border-b border-border pb-2 mb-4">
        <button
          onClick={() => setMobileTab("map")}
          className={\`px-4 py-2 text-sm font-medium rounded-t-lg \${mobileTab === "map" ? "bg-surface border-b-2 border-primary text-primary" : "text-text-subtle"}\`}
        >
          Map
        </button>
        <button
          onClick={() => setMobileTab("timeline")}
          className={\`px-4 py-2 text-sm font-medium rounded-t-lg \${mobileTab === "timeline" ? "bg-surface border-b-2 border-primary text-primary" : "text-text-subtle"}\`}
        >
          Timeline
        </button>
      </div>
      <div
        className={
          props.isFullscreen
            ? "min-h-0 flex-1 flex overflow-hidden"
            : "flex flex-col lg:flex-row items-stretch min-h-[calc(100dvh-12rem)] lg:flex-1"
        }
      >
        <div
          className={
            props.isFullscreen
              ? \`min-w-0 flex-1 h-full \${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col\`
              : \`min-w-0 flex-1 h-full \${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col\`
          }
        >
          <AuditNoticeRegion
            expiredSessionId={props.expiredSessionId}
            allSessions={props.allSessions}
            setExpiredSessionId={props.setExpiredSessionId}
            handleUserSelectSession={props.handleUserSelectSession}
            switchViewMode={props.switchViewMode}
            hasActiveFilters={props.hasActiveFilters}
            isSelectedFilteredOut={props.isSelectedFilteredOut}
            filteredSessionsCount={props.filteredSessionsCount}
            totalSessionsCount={props.totalSessionsCount}
            targetPathFilter={props.targetPathFilter}
            hideHomeOnly={props.hideHomeOnly}
            selectedSession={props.selectedSession}
            filteredActiveSessions={props.filteredActiveSessions}
            filteredClosedSessions={props.filteredClosedSessions}
            handleResetAuditFilters={props.handleResetAuditFilters}
            handleClearSelection={props.handleClearSelection}
          />
          {!props.isFullscreen && (
            <div className="mb-4">
              <AuditScopeBar
                filteredActiveSessions={props.filteredActiveSessions}
                filteredClosedSessions={props.filteredClosedSessions}
                selectedSessionId={props.selectedSessionId}
                handleUserSelectSession={props.handleUserSelectSession}
                totalSessionsCount={props.totalSessionsCount}
                hideHomeOnly={props.hideHomeOnly}
                targetPathFilter={props.targetPathFilter}
                handleResetAuditFilters={props.handleResetAuditFilters}
                allSessions={props.allSessions}
                directoryHasMore={props.directoryHasMore}
                directoryIsLoading={props.directoryIsLoading}
                directoryIsComplete={props.directoryIsComplete}
                loadMoreDirectory={props.loadMoreDirectory}
                auditSearchItems={props.auditSearchItems}
                auditSearchHasMore={props.auditSearchHasMore}
                auditSearchIsLoading={props.auditSearchIsLoading}
                auditSearchIsComplete={props.auditSearchIsComplete}
                searchAuditSessions={props.searchAuditSessions}
                loadMoreAuditSearch={props.loadMoreAuditSearch}
                clearAuditSearch={props.clearAuditSearch}
                auditStatus={props.auditStatus}
                auditErrorMessage={props.auditErrorMessage}
                retryInitialDirectory={props.retryInitialDirectory}
                handleToggleHideHomeOnly={props.handleToggleHideHomeOnly}
                handleSelectTargetPath={props.handleSelectTargetPath}
                distinctPaths={props.distinctPaths}
                homeOnlyCount={props.homeOnlyCount}
                filteredSessionsCount={props.filteredSessionsCount}
                selectedPath={props.selectedPath}
              />
            </div>
          )}
          <TopologyCanvas`;

code = code.replace(/export function AuditFilesystemWorkspace[^]*?<AuditNoticeRegion[^]*?\/>\s*<TopologyCanvas/, funcHeader);

// Fix timeline display
const timelineSplitter = `{!props.isTimelineCollapsed && (
        <TimelineSplitter
          isDragging={props.isDraggingTimeline}
          width={props.timelineWidth}
          onMouseDown={props.handleSplitterMouseDown}
          onDoubleClick={props.handleResetTimelineWidth}
          onKeyDown={props.handleSplitterKeyDown}
          className={props.isFullscreen ? "hidden sm:flex" : "hidden lg:flex"}
        />
      )}

      <div className={\`\${mobileTab === "timeline" ? "flex" : "hidden"} lg:flex h-full\`}>
        <FilesystemTimelinePanel`;

code = code.replace(/\{!props\.isTimelineCollapsed && \(\s*<TimelineSplitter[^]*?\/>\s*\)\}\s*<FilesystemTimelinePanel/, timelineSplitter);

// Close the div wrapping FilesystemTimelinePanel and the main container
code = code.replace(/<\/div>\s*<\/div>\s*\);\s*\}/, "  />\n      </div>\n    </div>\n    </div>\n  );\n}");


fs.writeFileSync(path, code);
