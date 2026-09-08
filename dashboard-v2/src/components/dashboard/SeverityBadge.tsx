import { cn } from '@/lib/utils';
import { RiskLevel } from '@/types/honeypot';

export function SeverityBadge({ severity, className }: { severity: RiskLevel | string; className?: string }) {
  const colors = {
    Low: 'bg-success-subtle text-success border-success-border',
    Medium: 'bg-warning-subtle text-warning border-warning-border',
    High: 'bg-warning-subtle text-warning border-warning-border',
    Critical: 'bg-danger-subtle text-danger border-danger-border',
  };

  const badgeColor = colors[severity as keyof typeof colors] || "bg-neutral-subtle text-neutral border-neutral-border";
  const markerClass = severity === 'Critical' ? 'rounded-sm' : severity === 'High' ? 'rounded-[3px]' : 'rounded-full';

  return (
    <span className={cn('ui-badge', badgeColor, className)} aria-label={`Severity ${severity}`}>
      <span aria-hidden="true" className={cn('h-2 w-2 shrink-0 bg-current', markerClass)} />
      {severity}
    </span>
  );
}
