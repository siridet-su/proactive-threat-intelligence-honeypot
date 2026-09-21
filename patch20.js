const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-server.ts';
let code = fs.readFileSync(path, 'utf8');

const search = `  const homeOnly = typeof document.auditHomeOnly === "boolean"
    ? document.auditHomeOnly
    : (typeof document.homeOnly === "boolean" ? document.homeOnly : (hasHomePath && !hasOutsideHomePath));`;
const replace = `  const homeOnly = hasHomePath && !hasOutsideHomePath;`;

code = code.replace(search, replace);

fs.writeFileSync(path, code);
