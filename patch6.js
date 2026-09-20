const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const searchSessions = async \([\s\S]*?filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\n\s*\) => \{/m,
  `const searchSessions = async (query: string, cursor: string | null = null, filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

code = code.replace(
  /const loadMoreSearch = async \(filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => \{/g,
  `const loadMoreSearch = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

fs.writeFileSync(path, code);
