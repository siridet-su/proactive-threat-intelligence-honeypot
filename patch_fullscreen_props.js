const fs = require('fs');
const path = './dashboard-v2/src/components/filesystem/FilesystemActivity.tsx';
let code = fs.readFileSync(path, 'utf8');

const additionalProps = \`
            directoryHasMore={directoryHasMore}
            directoryIsLoading={directoryIsLoading}
            directoryIsComplete={directoryIsComplete}
            loadMoreDirectory={loadMoreDirectory}
            auditSearchItems={auditSearchItems}
            auditSearchHasMore={auditSearchHasMore}
            auditSearchIsLoading={auditSearchIsLoading}
            auditSearchIsComplete={auditSearchIsComplete}
            searchAuditSessions={(q) => void searchAuditSessions(q)}
            loadMoreAuditSearch={loadMoreAuditSearch}
            clearAuditSearch={clearAuditSearch}
            auditStatus={auditStatus}
            auditErrorMessage={auditErrorMessage}
            retryInitialDirectory={retryInitialDirectory}
            handleToggleHideHomeOnly={handleToggleHideHomeOnly}
            handleSelectTargetPath={handleSelectTargetPath}
            distinctPaths={distinctPaths}
            homeOnlyCount={homeOnlyCount}\`;

// Add props to the first instance (Fullscreen)
code = code.replace(/(<AuditFilesystemWorkspace\s*isFullscreen=\{true\}[^]*?handleClearSelection=\{handleClearSelection\})/, "$1" + additionalProps);

// Add props to the second instance (Inline)
code = code.replace(/(<AuditFilesystemWorkspace\s*isFullscreen=\{false\}[^]*?handleClearSelection=\{handleClearSelection\})/, "$1" + additionalProps);

fs.writeFileSync(path, code);
