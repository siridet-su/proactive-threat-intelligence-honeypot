const fs = require('fs');
let code = fs.readFileSync('dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx', 'utf8');
code = code.replace(/props\.isFullscreen/g, 'isFullscreen');
code = code.replace(/props\.onToggleFullscreen/g, 'onToggleFullscreen');
fs.writeFileSync('dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx', code);
