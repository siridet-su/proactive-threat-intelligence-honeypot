const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /searchSessions: \(query: string, cursor: string \| null, filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => Promise<void>;/g,
  `searchSessions: (query: string, cursor: string | null, filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => Promise<void>;`
);

code = code.replace(
  /loadMoreSearch: \(filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => Promise<void>;/g,
  `loadMoreSearch: (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => Promise<void>;`
);

code = code.replace(
  /const searchSessions = async \(query: string, cursor: string \| null = null, filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => \{/g,
  `const searchSessions = async (query: string, cursor: string | null = null, filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

code = code.replace(
  /const loadMoreSearch = async \(filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => \{/g,
  `const loadMoreSearch = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

fs.writeFileSync(path, code);
