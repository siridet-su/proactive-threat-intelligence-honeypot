const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const params = new URLSearchParams\(\);\n\s*if \(hideHome\) params.set\("hideHome", "1"\);\n\s*if \(targetPath\) params.set\("targetPath", targetPath\);/g,
  `const params = new URLSearchParams();\n      if (hideHome) params.set("hideHome", "1");\n      if (targetPath) params.set("targetPath", targetPath);\n      if (options?.from != null) params.set("from", String(options.from));\n      if (options?.to != null) params.set("to", String(options.to));`
);

code = code.replace(
  /const params = new URLSearchParams\(\);\n\s*if \(scope.hideHome\) params.set\("hideHome", "1"\);\n\s*if \(scope.targetPath\) params.set\("targetPath", scope.targetPath\);\n\s*if \(scope.q\?\.trim\(\)\) params.set\("q", scope.q.trim\(\)\);/g,
  `const params = new URLSearchParams();\n      if (scope.hideHome) params.set("hideHome", "1");\n      if (scope.targetPath) params.set("targetPath", scope.targetPath);\n      if (scope.q?.trim()) params.set("q", scope.q.trim());\n      if (scope.from != null) params.set("from", String(scope.from));\n      if (scope.to != null) params.set("to", String(scope.to));`
);

code = code.replace(
  /const params = new URLSearchParams\(\);\n\s*if \(state.directoryCursor\) params.set\("cursor", state.directoryCursor\);\n\s*if \(parsedScope.hideHome\) params.set\("hideHome", "1"\);\n\s*if \(parsedScope.targetPath\) params.set\("targetPath", parsedScope.targetPath\);/g,
  `const params = new URLSearchParams();\n      if (state.directoryCursor) params.set("cursor", state.directoryCursor);\n      if (parsedScope.hideHome) params.set("hideHome", "1");\n      if (parsedScope.targetPath) params.set("targetPath", parsedScope.targetPath);\n      if (parsedScope.from != null) params.set("from", String(parsedScope.from));\n      if (parsedScope.to != null) params.set("to", String(parsedScope.to));`
);

code = code.replace(
  /const params = new URLSearchParams\(\);\n\s*if \(state.searchCursor\) params.set\("cursor", state.searchCursor\);\n\s*if \(parsedScope.hideHome\) params.set\("hideHome", "1"\);\n\s*if \(parsedScope.targetPath\) params.set\("targetPath", parsedScope.targetPath\);\n\s*if \(parsedScope.q\?\.trim\(\)\) params.set\("q", parsedScope.q.trim\(\)\);/g,
  `const params = new URLSearchParams();\n      if (state.searchCursor) params.set("cursor", state.searchCursor);\n      if (parsedScope.hideHome) params.set("hideHome", "1");\n      if (parsedScope.targetPath) params.set("targetPath", parsedScope.targetPath);\n      if (parsedScope.q?.trim()) params.set("q", parsedScope.q.trim());\n      if (parsedScope.from != null) params.set("from", String(parsedScope.from));\n      if (parsedScope.to != null) params.set("to", String(parsedScope.to));`
);

code = code.replace(
  /fetchInitial = async \(filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => \{/g,
  `fetchInitial = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

code = code.replace(
  /retryInitial = async \(filterOptions\?: \{ hideHome\?: boolean; targetPath\?: string \| null \}\) => \{/g,
  `retryInitial = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {`
);

fs.writeFileSync(path, code);
