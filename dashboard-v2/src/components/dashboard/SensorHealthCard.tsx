import { SensorHealth } from '@/types/honeypot';
import { StatusBadge } from './StatusBadge';

interface SensorHealthCardProps {
  sensors: SensorHealth[];
}

export function SensorHealthCard({ sensors }: SensorHealthCardProps) {
  return (
    <div className="flex flex-col gap-3">
      {sensors.map((sensor, i) => (
        <div key={i} className="ui-panel-interactive rounded-lg border border-border bg-surface-subtle p-3">
          <div className="flex justify-between items-center mb-2">
            <span className="font-medium text-text">{sensor.name}</span>
            <StatusBadge status={sensor.status} />
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="flex flex-col">
              <span className="text-text-subtle">Uptime</span>
              <span className="font-mono text-text">{sensor.uptime}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-text-subtle">Latency</span>
              <span className="font-mono text-text">{sensor.latency}</span>
            </div>
            <div className="flex flex-col col-span-2">
              <span className="text-text-subtle">Events processed</span>
              <span className="font-mono text-text">{sensor.eventsProcessed.toLocaleString()}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
