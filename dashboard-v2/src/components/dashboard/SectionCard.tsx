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
      'ui-panel flex flex-col overflow-hidden',
      className
    )}>
      <div className="flex flex-wrap items-center justify-between gap-4 px-6 py-5 border-b border-border">
        <div className="flex items-center gap-2">
          {icon && <span className="text-primary">{icon}</span>}
          <h3 className="text-base font-semibold text-text">{title}</h3>
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="p-6 flex-1">
        {children}
      </div>
    </div>
  );
}
