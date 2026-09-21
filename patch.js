const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');
code = code.replace(
`export function normalizeAuditScopeTargetPath(targetPath?: string | null): string | null {
  if (!targetPath) return null;
  const t = targetPath.trim();
  return t === "" ? null : t;
}`,
`export function normalizeAuditScopeTargetPath(path: string | null | undefined): string | null {
  if (!path) return null;
  const trimmed = path.trim();
  if (!trimmed) return null;
  const stripped = trimmed.replace(/\\/+$/, "");
  return stripped || "/";
}`
);
code = code.replace(
`export function normalizeAuditScopeQuery(q?: string | null): string | null {
  if (!q) return null;
  const t = q.trim();
  return t === "" ? null : t;
}`,
`export function normalizeAuditScopeQuery(q: string | null | undefined): string | null {
  if (!q) return null;
  const trimmed = q.trim();
  return trimmed ? trimmed.toLowerCase() : null;
}`
);
fs.writeFileSync(path, code);
