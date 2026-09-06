import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  status: 'Online' | 'Offline' | 'Degraded';
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const colors = {
    Online: 'bg-success-subtle text-success border-success-border',
    Degraded: 'bg-warning-subtle text-warning border-warning-border',
    Offline: 'bg-danger-subtle text-danger border-danger-border',
  };

  return (
    <span className={cn('ui-badge', colors[status], className)}>
      <span className={cn('w-1.5 h-1.5 rounded-full', {
        'bg-success': status === 'Online',
        'bg-warning': status === 'Degraded',
        'bg-danger': status === 'Offline',
      })} />
      {status}
    </span>
  );
}
