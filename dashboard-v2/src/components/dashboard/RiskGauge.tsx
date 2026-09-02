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
    if (normalizedScore < 40) return 'text-emerald-500';
    if (normalizedScore < 70) return 'text-amber-500';
    if (normalizedScore < 90) return 'text-orange-500';
    return 'text-red-500';
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
            className="text-slate-800"
          />
          {/* Foreground Arc */}
          <path
            d="M 10 50 A 40 40 0 0 1 90 50"
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            className={cn('transition-all duration-1000 ease-out drop-shadow-[0_0_8px_currentColor]', getColor())}
          />
        </svg>
        <div className="absolute bottom-0 left-0 right-0 text-center translate-y-2">
          <span className="text-4xl font-black text-slate-100 drop-shadow-md">{score}</span>
          <span className="text-sm font-medium text-slate-400 ml-1">/100</span>
        </div>
      </div>
      
      <div className={cn(
        'mt-6 px-4 py-1.5 rounded-full border text-sm font-bold tracking-widest uppercase shadow-[0_0_15px_rgba(0,0,0,0.2)]',
        normalizedScore < 40 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
        normalizedScore < 70 ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
        normalizedScore < 90 ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
        'bg-red-500/10 text-red-400 border-red-500/30 animate-pulse'
      )}>
        {label} RISK
      </div>
    </div>
  );
}
