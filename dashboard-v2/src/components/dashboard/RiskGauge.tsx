import { cn } from '@/lib/utils';
import { RiskLevel } from '@/types/honeypot';

interface RiskGaugeProps {
  score: number; // 0-100
  label: RiskLevel;
}

export function RiskGauge({ score, label }: RiskGaugeProps) {
  const normalizedScore = Math.min(100, Math.max(0, score));
  
  // Calculate stroke dasharray for a half circle
  // Circumference of a circle with r=40 is ~251.2
  const circumference = 251.2;
  const strokeDasharray = `${(normalizedScore / 100) * (circumference / 2)} ${circumference}`;

  const getColor = () => {
    if (normalizedScore < 40) return 'text-success';
    if (normalizedScore < 70) return 'text-warning';
    return 'text-danger';
  };

  return (
    <div className="flex flex-col items-center justify-center relative py-4">
      <div className="relative w-48 h-24 overflow-hidden">
        <svg viewBox="0 0 100 50" className="w-full h-full overflow-visible">
          {/* Background Arc */}
          <path
            d="M 10 50 A 40 40 0 0 1 90 50"
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeLinecap="round"
            className="text-border"
          />
          {/* Foreground Arc */}
          <path
            d="M 10 50 A 40 40 0 0 1 90 50"
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            className={cn('transition-colors duration-150', getColor())}
          />
        </svg>
        <div className="absolute bottom-0 left-0 right-0 text-center translate-y-2">
          <span className="text-3xl font-semibold text-text">{score}</span>
          <span className="ml-1 text-sm font-medium text-text-muted">/100</span>
        </div>
      </div>
      
      <div className={cn(
        'ui-badge mt-6',
        normalizedScore < 40 ? 'bg-success-subtle text-success border-success-border' :
        normalizedScore < 70 ? 'bg-warning-subtle text-warning border-warning-border' :
        'bg-danger-subtle text-danger border-danger-border'
      )}>
        {label} RISK
      </div>
    </div>
  );
}
