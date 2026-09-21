const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /export interface UseAuditDirectoryOptions \{/g,
  `import type { DateRange } from "react-day-picker";\nexport interface UseAuditDirectoryOptions {`
);

code = code.replace(
  /targetPathFilter\?: string \| null;\n\}/g,
  `targetPathFilter?: string | null;\n  timeRange?: TimeRangeFilter;\n  customDateRange?: DateRange;\n}`
);

code = code.replace(
  /targetPathFilter = null,\n\}: UseAuditDirectoryOptions\) \{/g,
  `targetPathFilter = null,\n  timeRange = "all",\n  customDateRange,\n}: UseAuditDirectoryOptions) {`
);

fs.writeFileSync(path, code);
