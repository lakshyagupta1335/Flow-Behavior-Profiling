import { useAnalysis } from '../AnalysisContext';
import { ThroughputChart } from './ThroughputChart';
import { ProtocolPieChart } from './ProtocolPieChart';
import { ClassificationPieChart } from './ClassificationPieChart';

export function LiveMetricsPanel() {
  const { result, networkMetrics } = useAnalysis();

  let inboundCount = 0;
  let outboundCount = 0;
  let balancedCount = 0;

  result?.rows.forEach(row => {
    const dir = row['Direction'];

    if (dir === "Inbound Heavy") inboundCount++;
    else if (dir === "Outbound Heavy") outboundCount++;
    else if (dir === "Balanced") balancedCount++;
  });

  const displayMetrics = {
    total: networkMetrics?.flows ?? 0,

    avgThroughput: networkMetrics?.avg_throughput_mbps ?? 0,
    avgUpload: networkMetrics?.avg_upload_mbps ?? 0,
    avgDownload: networkMetrics?.avg_download_mbps ?? 0,

    avgPacketRate: networkMetrics?.avg_packet_rate_pps ?? 0,
    avgPacketSize: networkMetrics?.avg_packet_size ?? 0,

    inbound: inboundCount,
    outbound: outboundCount,
    balanced: balancedCount,
  };

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-center">

        {/* Row 1 */}
        <MetricBox label="Average Data Flow Rate (Mbps)" value={displayMetrics.avgThroughput} color="green" />
        <MetricBox label="Average Outbound Rate (Mbps)" value={displayMetrics.avgUpload} color="purple" />
        <MetricBox label="Average Inbound Rate (Mbps)" value={displayMetrics.avgDownload} color="green" />

        {/* Row 2 */}
        <div className="md:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-3">
        <MetricBox label="Packet Rate (pps)" value={displayMetrics.avgPacketRate} color="blue" />
        <MetricBox label="Average Packet Size (Bytes)" value={displayMetrics.avgPacketSize} color="blue" />
        </div>

        {/* Flow count */}
        <div className="col-span-3 text-center font-bold my-2 text-gray-700">
          Total Flows: {displayMetrics.total.toLocaleString()}
        </div>

        {/* Direction */}
        <MetricBox label="Balanced" value={displayMetrics.balanced} color="green" />
        <MetricBox label="Inbound Heavy" value={displayMetrics.inbound} color="purple" />
        <MetricBox label="Outbound Heavy" value={displayMetrics.outbound} color="blue" />
      </div>

      {/* Charts */}
      <ThroughputChart />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
        <ClassificationPieChart />
        <ProtocolPieChart />
      </div>
    </>
  );
}

function MetricBox({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  const colors: Record<string, string> = {
    blue: 'text-blue-600 bg-blue-50 border-blue-200',
    green: 'text-green-600 bg-green-50 border-green-200',
    gray: 'text-gray-600 bg-gray-50 border-gray-200',
    red: 'text-red-600 bg-red-50 border-red-200',
    purple: 'text-purple-600 bg-purple-50 border-purple-200',
    orange: 'text-orange-600 bg-orange-50 border-orange-200',
  };

  return (
    <div className={`p-4 rounded-lg border shadow-sm transition-all duration-200 ${colors[color]}`}>
      <div className="text-[12px] font-bold opacity-70 tracking-wider">
        {label}
      </div>
      <div className="text-2xl font-black mt-1">
        {Number(value).toLocaleString()}
      </div>
    </div>
  );
}


