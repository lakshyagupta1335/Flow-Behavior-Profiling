import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { useAnalysis } from '../AnalysisContext';

export function ClassificationPieChart() {
  const { result } = useAnalysis();


  const summaryData = result?.summary ?? {
    Normal: 0,
    Suspicious: 0,
    'Attack-like': 0,
    Anomaly: 0,
    Misconfigured: 0
  };


  const data = [
    { name: 'Normal', value: summaryData.Normal },
    { name: 'Suspicious', value: summaryData.Suspicious },
    { name: 'Attack-like', value: summaryData['Attack-like'] },
    { name: 'Misconfigured', value: summaryData['Misconfigured'] },
    { name: 'Anomaly', value: summaryData.Anomaly },
  ].filter(item => item.value >= 0); 

  
  const COLORS = {
    'Normal': '#10B981',      
    'Suspicious': '#F59E0B',  
    'Attack-like': '#EF4444', 
    'Anomaly': '#8B5CF6',     
  };


  const totalFlows = data.reduce((sum, entry) => sum + entry.value, 0);

  return (
    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm flex flex-col h-[320px]">
      <div className="mb-2">
        <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wider">
          Classification Distribution
        </h3>
        <p className="text-xs text-gray-400">Real-time threat profile status</p>
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
                innerRadius={60}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
              >
                {data.map((entry) => (
                  <Cell 
                    key={`cell-${entry.name}`} 
                    fill={COLORS[entry.name as keyof typeof COLORS] || '#9CA3AF'} 
                  />
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

