import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  status: 'Online' | 'Offline' | 'Degraded';
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const colors = {
    Online: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    Degraded: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    Offline: 'bg-red-500/10 text-red-400 border-red-500/20',
  };

  return (
    <span className={cn('flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium border', colors[status], className)}>
      <span className={cn('w-1.5 h-1.5 rounded-full', {
        'bg-emerald-400 animate-pulse': status === 'Online',
        'bg-amber-400': status === 'Degraded',
        'bg-red-400': status === 'Offline',
      })} />
      {status}
    </span>
  );
}
