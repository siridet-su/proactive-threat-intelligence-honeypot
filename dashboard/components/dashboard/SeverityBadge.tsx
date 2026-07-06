import { cn } from '@/lib/utils';
import { RiskLevel } from '@/types/honeypot';

export function SeverityBadge({ severity, className }: { severity: RiskLevel | string; className?: string }) {
  const colors = {
    Low: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    Medium: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    High: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    Critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  };

  const badgeColor = colors[severity as keyof typeof colors] || colors.Low;

  return (
    <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium border', badgeColor, className)}>
      {severity}
    </span>
  );
}
