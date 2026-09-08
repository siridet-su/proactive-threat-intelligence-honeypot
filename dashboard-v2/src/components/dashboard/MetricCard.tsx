import { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { MiniSparkline } from './MiniSparkline';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  trend: number; // positive = up, negative = down, 0 = neutral
  sparklineData?: number[];
  sparklineColor?: string;
  className?: string;
}

export function MetricCard({ title, value, icon, trend, sparklineData, sparklineColor = 'var(--chart-1)', className }: MetricCardProps) {
  const isPositive = trend > 0;
  const isNegative = trend < 0;

  return (
    <div className={cn(
      'ui-panel p-6',
      className
    )}>
      <div className="flex justify-between items-start mb-4 relative z-10">
        <div className="p-2.5 bg-primary-subtle rounded-lg text-primary border border-primary-border">
          {icon}
        </div>

        <div className={cn(
          'flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md border',
          isPositive ? 'text-danger bg-danger-subtle border-danger-border' :
          isNegative ? 'text-success bg-success-subtle border-success-border' :
          'text-neutral bg-neutral-subtle border-neutral-border'
        )}>
          {isPositive ? <TrendingUp className="w-3 h-3" /> :
           isNegative ? <TrendingDown className="w-3 h-3" /> :
           <Minus className="w-3 h-3" />}
          {Math.abs(trend)}%
        </div>
      </div>

      <div className="flex justify-between items-end relative z-10">
        <div>
          <p className="text-text-muted text-sm font-medium mb-1">{title}</p>
          <h4 className="text-2xl font-semibold text-text tabular-nums">{value}</h4>
        </div>

        {sparklineData && (
          <div className="shrink-0">
            <MiniSparkline data={sparklineData} color={sparklineColor} />
          </div>
        )}
      </div>
    </div>
  );
}
