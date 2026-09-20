const fs = require('fs');
const path = './dashboard-v2/src/components/filesystem/FilesystemActivity.tsx';
let code = fs.readFileSync(path, 'utf8');

const liveModeRegex = /\{\/\* Mode 1: Live Global Topology Mode \*\/\}\s*\{viewMode === "live" \? \(\s*<div className="grid gap-6 xl:grid-cols-\[minmax\(0,1fr\)_22rem\] xl:items-start">\s*<div className="min-w-0">/m;

const replacement = \`{/* Mode 1: Live Global Topology Mode */}
      {viewMode === "live" ? (
        <div className="flex flex-col lg:grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start min-h-[calc(100dvh-12rem)] lg:flex-1">
          {/* Mobile Tabs */}
          <div className="flex lg:hidden gap-2 border-b border-border pb-2">
            <button
              onClick={() => setMobileTab('map')}
              className={\`px-4 py-2 text-sm font-medium rounded-t-lg \${mobileTab === 'map' ? 'bg-surface border-b-2 border-primary text-primary' : 'text-text-subtle'}\`}
            >
              Map
            </button>
            <button
              onClick={() => setMobileTab('details')}
              className={\`px-4 py-2 text-sm font-medium rounded-t-lg \${mobileTab === 'details' ? 'bg-surface border-b-2 border-primary text-primary' : 'text-text-subtle'}\`}
            >
              Details
            </button>
          </div>

          <div className={\`min-w-0 flex-col gap-4 \${mobileTab === 'map' ? 'flex' : 'hidden'} lg:flex h-full\`}>
            <LiveScopeBar snapshot={snapshot} />\`;

code = code.replace(liveModeRegex, replacement);

const detailsPanelRegex = /<FilesystemContextPanel\s*selectedSession=\{selectedSession\}/m;
const detailsReplacement = \`<div className={\`\${mobileTab === 'details' ? 'block' : 'hidden'} lg:block h-full\`}>
            <FilesystemContextPanel
              selectedSession={selectedSession}\`;

code = code.replace(detailsPanelRegex, detailsReplacement);

// Fix the closing div for Mode 1
const mode1ClosingRegex = /onOpenAudit=\{\(sessionId\) => switchViewMode\("audit", sessionId\)\}\s*\/>\s*<\/div>\s*\)\ : isAuditFullscreen \? \(/m;
const mode1ClosingReplacement = \`onOpenAudit={(sessionId) => switchViewMode("audit", sessionId)}
            />
          </div>
        </div>
      ) : isAuditFullscreen ? (\`;

code = code.replace(mode1ClosingRegex, mode1ClosingReplacement);

fs.writeFileSync(path, code);
