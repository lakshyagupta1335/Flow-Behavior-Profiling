import { useEffect, useState } from 'react';
import { useAnalysis } from '../AnalysisContext';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface ChartData {
  name: string;
  value: number;
}

const COLORS = [
  '#0088FE',
  '#00C49F',
  '#FFBB28',
  '#FF8042',
  '#A28DFF',
  '#FF6666',
];

export function ProtocolPieChart() {
  const { result } = useAnalysis();
  const [data, setData] = useState<ChartData[]>([]);

  useEffect(() => {
    if (!result?.rows?.length) {
      setData([]);
      return;
    }

    const map: Record<string, number> = {};

    result.rows.forEach((row) => {
      const proto = row['Protocol'] || 'OTHER';
      map[proto] = (map[proto] || 0) + 1;
    });

    const chartData = Object.keys(map).map((key) => ({
      name: key,
      value: map[key],
    }));

    setData(chartData);
  }, [result?.rows]);

  const totalFlows = data.reduce((sum, entry) => sum + entry.value, 0);

  return (
    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm flex flex-col h-[320px]">
      <div className="mb-2">
        <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wider">
          Protocol Distribution
        </h3>
        <p className="text-xs text-gray-400">Real-time protocol activity profile</p>
      </div>

      <div className="flex-1 w-full h-full min-h-[200px]">
        {totalFlows === 0 ? (
          <div className="w-full h-full flex items-center justify-center text-xs text-gray-400 italic">
            Waiting for network flows...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="45%"
                outerRadius={80} // Removed innerRadius and paddingAngle to make it a normal, solid pie
                dataKey="value"
                nameKey="name"
              >
                {data.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{ backgroundColor: '#fff', borderRadius: '6px', border: '1px solid #E5E7EB', fontSize: '12px' }}
                formatter={(value: number, name: string) => {
                  const percentage = totalFlows > 0 ? ((value / totalFlows) * 100).toFixed(1) : '0';
                  return [`${value.toLocaleString()} flows (${percentage}%)`, name];
                }}
              />

              <Legend 
                verticalAlign="bottom" 
                height={36}
                iconType="circle"
                iconSize={8}
                wrapperStyle={{ fontSize: '11px', fontWeight: 'bold' }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
