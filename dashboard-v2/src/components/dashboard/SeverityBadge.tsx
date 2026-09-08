import { cn } from '@/lib/utils';
import { RiskLevel } from '@/types/honeypot';
import { severityBadgeClass } from '@/lib/presentation';

export function SeverityBadge({ severity, className }: { severity: RiskLevel | string; className?: string }) {
  const badgeColor = severityBadgeClass(severity);
  const markerClass = severity === 'Critical' ? 'rounded-sm' : severity === 'High' ? 'rounded-[3px]' : 'rounded-full';

  return (
    <span className={cn('ui-badge', badgeColor, className)} aria-label={`Severity ${severity}`}>
      <span aria-hidden="true" className={cn('h-2 w-2 shrink-0 bg-current', markerClass)} />
      {severity}
    </span>
  );
}
