'use client';

import { ResponsiveContainer, LineChart, Line } from 'recharts';

interface MiniSparklineProps {
  data: number[];
  color: string;
}

export function MiniSparkline({ data, color }: MiniSparklineProps) {
  const chartData = data.map((value, index) => ({ value, index }));

  return (
    <div className="h-10 w-24">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData}>
          <Line 
            type="monotone" 
            dataKey="value" 
            stroke={color} 
            strokeWidth={2} 
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
