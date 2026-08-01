import { SensorHealth } from '@/types/honeypot';
import { StatusBadge } from './StatusBadge';

interface SensorHealthCardProps {
  sensors: SensorHealth[];
}

export function SensorHealthCard({ sensors }: SensorHealthCardProps) {
  return (
    <div className="flex flex-col gap-3">
      {sensors.map((sensor, i) => (
        <div key={i} className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-3 hover:bg-slate-800/50 transition-colors">
          <div className="flex justify-between items-center mb-2">
            <span className="font-medium text-slate-200">{sensor.name}</span>
            <StatusBadge status={sensor.status} />
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="flex flex-col">
              <span className="text-slate-500">Uptime</span>
              <span className="text-slate-300 font-mono">{sensor.uptime}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-500">Latency</span>
              <span className="text-slate-300 font-mono">{sensor.latency}</span>
            </div>
            <div className="flex flex-col col-span-2">
              <span className="text-slate-500">Events Processed</span>
              <span className="text-slate-300 font-mono">{sensor.eventsProcessed.toLocaleString()}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
