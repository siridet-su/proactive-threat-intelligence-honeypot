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

export function MetricCard({ title, value, icon, trend, sparklineData, sparklineColor = '#3b82f6', className }: MetricCardProps) {
  const isPositive = trend > 0;
  const isNegative = trend < 0;
  
  return (
    <div className={cn(
      'bg-slate-900/60 border border-slate-800 rounded-xl p-5 backdrop-blur-sm',
      'shadow-lg hover:border-slate-700 hover:shadow-cyan-900/20 transition-all duration-300 relative overflow-hidden group',
      className
    )}>
      {/* Decorative gradient blob */}
      <div className="absolute -top-10 -right-10 w-24 h-24 bg-cyan-500/10 rounded-full blur-2xl group-hover:bg-cyan-500/20 transition-all duration-500" />
      
      <div className="flex justify-between items-start mb-4 relative z-10">
        <div className="p-2.5 bg-slate-800/80 rounded-lg text-cyan-400 border border-slate-700/50">
          {icon}
        </div>
        
        <div className={cn(
          'flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md border',
          isPositive ? 'text-red-400 bg-red-500/10 border-red-500/20' : 
          isNegative ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : 
          'text-slate-400 bg-slate-800 border-slate-700'
        )}>
          {isPositive ? <TrendingUp className="w-3 h-3" /> : 
           isNegative ? <TrendingDown className="w-3 h-3" /> : 
           <Minus className="w-3 h-3" />}
          {Math.abs(trend)}%
        </div>
      </div>
      
      <div className="flex justify-between items-end relative z-10">
        <div>
          <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
          <h4 className="text-2xl font-bold text-slate-100 tracking-tight">{value}</h4>
        </div>
        
        {sparklineData && (
          <div className="opacity-80 group-hover:opacity-100 transition-opacity">
            <MiniSparkline data={sparklineData} color={sparklineColor} />
          </div>
        )}
      </div>
    </div>
  );
}
