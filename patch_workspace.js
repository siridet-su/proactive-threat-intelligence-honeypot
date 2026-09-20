const fs = require('fs');
let code = fs.readFileSync('dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx', 'utf8');

// Remove unused imports
code = code.replace(/import type \{ FilesystemClosedSession, FilesystemTopologySession, FilesystemTopologySnapshot \} from "@\/lib\/dashboardTypes";\n/, '');
code = code.replace(/import type \{ ForensicTab \} from ".\/FilesystemActivity";\n/, '');
code = code.replace(/\/\* eslint-disable @typescript-eslint\/no-explicit-any \*\/\n/, '');

fs.writeFileSync('dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx', code);
