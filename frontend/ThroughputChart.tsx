import { useEffect, useState } from 'react';
import { useAnalysis } from '../AnalysisContext';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid
} from 'recharts';

export function ThroughputChart() {
  const { result } = useAnalysis();
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    if (!result?.rows?.length) {
      setData([]);
      return;
  }

    const ordered = [...result.rows].reverse();

    const last20 = ordered.slice(-20);

    const chartData = last20.map((row, i) => ({
      index: result.rows.length - last20.length + i + 1,
      'Data Flow Rate': Number(row['Throughput (Mbps)'] || 0),
      'Outbound Rate': Number(row['Upload (Mbps)'] || 0),
      'Inbound Rate': Number(row['Download (Mbps)'] || 0)
    }));

    setData(chartData);
  }, [result?.rows]);

  return (
    <div className="w-full h-80 bg-white p-4 rounded-xl shadow-md">
      <h2 className="text-sm font-bold mb-2">
        Real-Time Flow Rate (Mbps)
      </h2>

      <ResponsiveContainer width="100%" height="90%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />

          <XAxis
            dataKey="index" height={50}
            label={{ value: "Flow Sequence (Last 20 Flows)", position: "insideBottom", offset: -1 }}
          />

          <YAxis />

          <Tooltip formatter={(value: any) => Number(value).toFixed(2)} />

          {/* Data Flow Rate */}
          <Line
            type="monotone"
            dataKey="Data Flow Rate"
            stroke="#0088FE"
            strokeWidth={2}
            dot={false}
          />

          {/* Outbound Rate */}
          <Line
            type="monotone"
            dataKey="Outbound Rate"
            stroke="#00C49F"
            strokeWidth={2}
            dot={false}
          />

          {/* Inbound Rate */}
          <Line
            type="monotone"
            dataKey="Inbound Rate"
            stroke="#FF8042"
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
