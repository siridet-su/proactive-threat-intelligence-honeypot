const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

const hookStart = /export function useAuditDirectory\([^)]+\)\s*\{/;
const computedTimeRange = `
  const timeRangeMs = useMemo(() => {
    if (!timeRange || timeRange === "all") return null;
    let from: number | undefined;
    let to: number | undefined;
    if (timeRange === "custom") {
      from = customDateRange?.from?.getTime();
      to = customDateRange?.to?.getTime();
    } else {
      const presetRange = getPresetDateRange(timeRange);
      from = presetRange?.from?.getTime();
      to = presetRange?.to?.getTime();
    }
    return { from, to };
  }, [timeRange, customDateRange]);
`;

code = code.replace(hookStart, (match) => {
  return match + computedTimeRange;
});

fs.writeFileSync(path, code);
