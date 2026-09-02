import { cn } from '@/lib/utils';
import { ReactNode } from 'react';

interface SectionCardProps {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}

export function SectionCard({ title, icon, children, className, action }: SectionCardProps) {
  return (
    <div className={cn(
      'flex flex-col bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm',
      'shadow-[0_0_15px_rgba(0,0,0,0.5)] transition-all duration-300 hover:border-slate-700/80',
      className
    )}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900/80">
        <div className="flex items-center gap-2">
          {icon && <span className="text-cyan-400">{icon}</span>}
          <h3 className="font-semibold text-slate-200 tracking-wide">{title}</h3>
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="p-4 flex-1">
        {children}
      </div>
    </div>
  );
}
