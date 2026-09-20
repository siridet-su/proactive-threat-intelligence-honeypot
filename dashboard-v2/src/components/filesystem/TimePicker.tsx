import * as React from "react"
import { Clock } from "lucide-react"

interface TimePickerProps {
  date?: Date;
  onChange: (date: Date) => void;
  label: string;
}

export function TimePicker({ date, onChange, label }: TimePickerProps) {
  const hours = Array.from({ length: 24 }, (_, i) => i);
  const minutes = Array.from({ length: 60 }, (_, i) => i);

  const selectedHour = date ? date.getHours() : 0;
  const selectedMinute = date ? date.getMinutes() : 0;

  const handleHourChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    if (!date) return;
    const newDate = new Date(date);
    newDate.setHours(parseInt(e.target.value, 10));
    onChange(newDate);
  };

  const handleMinuteChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    if (!date) return;
    const newDate = new Date(date);
    newDate.setMinutes(parseInt(e.target.value, 10));
    onChange(newDate);
  };

  return (
    <div className="flex items-center justify-between p-2 rounded-lg bg-surface-subtle border border-border/50 hover:border-primary/50 transition-colors">
      <div className="flex items-center gap-2">
        <Clock className="w-3.5 h-3.5 text-primary" />
        <span className="text-xs font-medium text-text">{label}</span>
      </div>
      <div className="flex items-center gap-1 bg-surface rounded-md border border-border px-1">
        <select
          value={selectedHour}
          onChange={handleHourChange}
          className="bg-transparent text-xs text-text p-1 outline-none appearance-none cursor-pointer hover:text-primary transition-colors"
          style={{ textAlignLast: "center" }}
        >
          {hours.map((h) => (
            <option key={h} value={h} className="bg-surface text-text">
              {h.toString().padStart(2, "0")}
            </option>
          ))}
        </select>
        <span className="text-text-subtle text-xs font-bold">:</span>
        <select
          value={selectedMinute}
          onChange={handleMinuteChange}
          className="bg-transparent text-xs text-text p-1 outline-none appearance-none cursor-pointer hover:text-primary transition-colors"
          style={{ textAlignLast: "center" }}
        >
          {minutes.map((m) => (
            <option key={m} value={m} className="bg-surface text-text">
              {m.toString().padStart(2, "0")}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
