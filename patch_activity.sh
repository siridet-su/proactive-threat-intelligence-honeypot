#!/bin/bash
sed -i '1s/^/import { FilesystemContext } from ".\/FilesystemContext";\n/' dashboard-v2/src/components/filesystem/FilesystemActivity.tsx

# Create context value
cat << 'JS_EOF' > patch_hook.js
const fs = require('fs');
let code = fs.readFileSync('dashboard-v2/src/components/filesystem/FilesystemActivity.tsx', 'utf8');

const contextValueStr = `
  const contextValue = {
    viewMode,
    mobileTab,
    setMobileTab,
    isAuditFullscreen,
    setIsAuditFullscreen,
    directoryHasMore,
    directoryIsLoading,
    directoryIsComplete,
    loadMoreDirectory,
    auditSearchItems,
    auditSearchHasMore,
    auditSearchIsLoading,
    auditSearchIsComplete,
    searchAuditSessions,
    loadMoreAuditSearch,
    clearAuditSearch,
    auditStatus,
    auditErrorMessage,
    retryInitialDirectory,
    handleToggleHideHomeOnly,
    handleSelectTargetPath,
    distinctPaths,
    homeOnlyCount,
    expiredSessionId,
    allSessions,
    setExpiredSessionId,
    handleUserSelectSession,
    switchViewMode,
    hasActiveFilters,
    isSelectedFilteredOut,
    filteredSessionsCount,
    totalSessionsCount,
    targetPathFilter,
    hideHomeOnly,
    selectedSession,
    filteredActiveSessions,
    filteredClosedSessions,
    handleResetAuditFilters,
    handleClearSelection,
    auditSnapshot,
    snapshot,
    regionStatus,
    streamState,
    freshnessState,
    selectedSessionId,
    selectedPath,
    activeHop,
    playbackSpeed,
    auditCanvasTitle,
    auditCanvasSubtitle,
    selectPath,
    refresh,
    handleReconnect,
    isDraggingTimeline,
    isTimelineCollapsed,
    timelineWidth,
    handleSplitterMouseDown,
    handleResetTimelineWidth,
    handleSplitterKeyDown,
    history,
    anchoredHop,
    historyStatus,
    historyCursor,
    historyTotalItems,
    historyTotalSuccessfulItems,
    historyComplete,
    replayPresentation,
    activeForensicTab,
    setActiveForensicTab,
    responsePanel,
    hopResolutionStatus,
    requestedHop,
    clearRequestedHop,
    selectLatestHop,
    handleSelectHistoryEventId,
    loadHistory,
  };

  return (
    <FilesystemContext.Provider value={contextValue as any}>
`;

code = code.replace(/return \(/, contextValueStr);

code = code.replace(/    <\/div>\n  \);\n\}/, '    </div>\n    </FilesystemContext.Provider>\n  );\n}');

fs.writeFileSync('dashboard-v2/src/components/filesystem/FilesystemActivity.tsx', code);
JS_EOF
node patch_hook.js
