import React, { useState, useEffect } from 'react';
import {
  CheckCircle, AlertCircle, AlertTriangle, Loader2,
  RefreshCw, Play, Square, ChevronRight
} from 'lucide-react';
import { useAnalysis, FlowRow } from '../AnalysisContext';

const LABEL_INFO: Record<string, string> = {
  BENIGN:
    "Traffic shows normal behavior: standard ports (80/443/53), stable packet size, and no abnormal rate spikes.",
  DDoS:
    "High traffic volume detected with large packet rates, low idle time, and continuous flow bursts indicating possible bandwidth flooding.",
  "DoS Hulk":
    "Large packet sizes combined with high request frequency and short flow intervals suggest HTTP flood attack behavior.",
  "DoS GoldenEye":
    "Persistent connections with medium packet sizes and high flow duration indicate slow HTTP exhaustion attack.",
  "DoS GoldenEye - Attempted":
    "Partial pattern of slow HTTP attack with incomplete connection saturation and inconsistent flow duration.",
  Portscan:
    "Very small packet sizes with extremely high forward packet rate indicate automated port scanning activity.",
  "Infiltration - Portscan":
    "Port scanning combined with irregular SYN/ACK patterns and elevated packet frequency suggesting stealth probing.",
  "Infiltration - Attempted":
    "Short-lived intrusion attempt with reset flags and incomplete connection establishment patterns.",
  "FTP-Patator":
    "Detected on port 21 with repeated connection attempts, moderate packet size bursts, and high request frequency.",
  "FTP-Patator - Attempted":
    "FTP login attempts observed but without sustained authentication success patterns.",
  "SSH-Patator":
    "Detected on port 22 with repeated login attempts, low packet size variance, and consistent authentication bursts.",
  "SSH-Patator - Attempted":
    "SSH brute force attempts detected with intermittent connection resets and low success probability patterns.",
  Botnet:
    "Repeated outbound communication patterns with consistent packet intervals and external IP contact behavior.",
  "Botnet - Attempted":
    "Suspicious periodic traffic to external hosts without stable command-and-control confirmation.",
  Heartbleed:
    "Large response packets with high memory-like variance and abnormal TLS heartbeat behavior detected.",
  Infiltration:
    "Irregular internal network traffic with unusual port usage and abnormal flow direction patterns.",
  Anomaly:
    "Statistical deviation detected in packet size, flow rate, or timing compared to normal baseline traffic.",
  "Attack-like":
    "Traffic shows suspicious patterns but does not match any specific known attack signature.",
  Unknown:
    "Insufficient feature confidence or incomplete flow data prevents classification."
};

export function Dashboard({ activeTab }: { activeTab: string }) {
  const {
    statusMsg, interfaces, fetchInterfaces,
    startCapture, stopCapture, isCapturing, result
  } = useAnalysis();

  const [selectedIface, setSelectedIface] = useState('');
  const [showPicker, setShowPicker] = useState(false);

  useEffect(() => {
    if (!isCapturing) {
      setShowPicker(false);
    }
  }, [isCapturing]);

  return (
    <div className="bg-gray-50 min-h-screen p-4 md:p-8">
      <div className="max-w-[92%] mx-auto space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
          <div>
            <h2 className="text-xl font-black text-gray-900 tracking-tight">Network Behavior Dashboard</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={`w-1.5 h-1.5 rounded-full ${isCapturing ? 'bg-green-500 animate-pulse' : 'bg-gray-300'}`} />
              <p className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">{statusMsg}</p>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-white px-2 py-1.5 rounded-md border border-gray-200 shadow-sm transition-all">
            {!showPicker && !isCapturing && (
              <button
                onClick={() => { setShowPicker(true); fetchInterfaces(); }}
                className="flex items-center gap-2 px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 transition-all shadow-sm"
              >
                <Play className="w-3 h-3 fill-current" />
                <span className="text-[10px] font-black uppercase tracking-widest">Start Session</span>
              </button>
            )}

            {showPicker && !isCapturing && (
              <>
                <button onClick={fetchInterfaces} className="p-1 hover:bg-gray-100 rounded text-blue-500 transition-colors">
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
                <select
                  className="text-[10px] font-black text-gray-500 uppercase bg-transparent outline-none border-x px-2 cursor-pointer"
                  value={selectedIface}
                  onChange={(e) => setSelectedIface(e.target.value)}
                >
                  <option value="">Select Interface</option>
                  {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
                </select>
                <button
                  onClick={() => startCapture(selectedIface)}
                  disabled={!selectedIface}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded transition-all ${selectedIface ? 'bg-green-600 text-white hover:bg-green-700' : 'bg-gray-100 text-gray-300'}`}
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                  <span className="text-[10px] font-black uppercase tracking-widest">Begin</span>
                </button>
              </>
            )}

            {isCapturing && (
              <button
                onClick={stopCapture}
                className="flex items-center gap-2 px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600 transition-all shadow-sm"
              >
                <Square className="w-3 h-3 fill-current" />
                <span className="text-[10px] font-black uppercase tracking-widest">Stop Capture</span>
              </button>
            )}
          </div>
        </div>

        {(!result || result.summary.total === 0) ? (
          <div className="bg-white rounded-lg border border-dashed border-gray-200 p-24 text-center flex flex-col items-center">
            <div className={`p-5 rounded-full mb-4 ${isCapturing ? 'bg-blue-50' : 'bg-gray-50'}`}>
              <Loader2 className={`w-10 h-10 ${isCapturing ? 'animate-spin text-blue-500' : 'text-gray-300'}`} />
            </div>
            <p className="text-xs font-bold text-gray-400 uppercase tracking-widest">
              {isCapturing ? `Monitoring incoming flows on ${selectedIface}...` : 'Engine idle. Click Start Session to begin.'}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {!isCapturing && (
              <div className="flex justify-center">
                <div className="bg-gray-100 border border-gray-200 text-gray-500 text-[10px] font-bold uppercase tracking-widest py-1 px-3 rounded-md shadow-sm">
                  Session Paused - Viewing Final Results
                </div>
              </div>
            )}

            {activeTab === 'overview'   && <OverviewTab />}
            {activeTab === 'normal'     && <CategoryTab category="normal" />}
            {activeTab === 'suspicious' && <CategoryTab category="suspicious" />}
            {activeTab === 'attack'     && <CategoryTab category="attack" />}
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewTab() {
  const { result } = useAnalysis();
  if (!result) return null;
  const { summary } = result;

  return (
    <div className="space-y-4 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row gap-4 w-full justify-center">
        <div className="flex-1">
          <MetricCard label="Anomalies Detected" value={summary.Anomaly.toLocaleString()} color="orange" />
        </div>
        <div className="flex-1">
          <MetricCard label="Total Live Flows" value={summary.total.toLocaleString()} color="gray" />
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <CategoryCountCard label="Normal" value={summary.Normal} icon={CheckCircle}
          borderColor="border-green-200" iconBg="bg-green-50" iconColor="text-green-600" />
        <CategoryCountCard label="Suspicious" value={summary.Suspicious} icon={AlertCircle}
          borderColor="border-yellow-200" iconBg="bg-yellow-50" iconColor="text-yellow-600" />
        <CategoryCountCard label="Attack-like" value={summary['Attack-like']} icon={AlertTriangle}
          borderColor="border-red-200" iconBg="bg-red-50" iconColor="text-red-600" />
      </div>
      <ResultsFlowTable rows={result.rows} filterCategory={null} />
    </div>
  );
}

function MetricCard({ label, value, color }: { label: string; value: string; color: string }) {
  const colors: Record<string, string> = {
    orange: 'border-orange-200 text-orange-700',
    gray: 'border-gray-200 text-gray-700',
  };
  return (
    <div className={`bg-white rounded-lg shadow-sm border p-4 text-center h-full flex flex-col justify-center ${colors[color]}`}>
      <div className="text-[10px] text-gray-400 mb-0.5 uppercase tracking-widest font-bold">{label}</div>
      <div className="text-3xl font-black">{value}</div>
    </div>
  );
}

function CategoryCountCard({ label, value, icon: Icon, borderColor, iconBg, iconColor }:
  { label: string; value: number; icon: React.ElementType; borderColor: string; iconBg: string; iconColor: string }) {
  return (
    <div className={`bg-white rounded-lg shadow-sm border ${borderColor} p-4 text-center`}>
      <div className="flex justify-center mb-2">
        <div className={`p-1.5 rounded-md ${iconBg}`}>
          <Icon className={`w-4 h-4 ${iconColor}`} />
        </div>
      </div>
      <div className="text-3xl font-black text-gray-900 leading-tight">{value.toLocaleString()}</div>
      <div className="text-[10px] text-gray-400 uppercase tracking-widest font-bold">{label}</div>
    </div>
  );
}

function ResultsFlowTable({ rows, filterCategory }: { rows: FlowRow[]; filterCategory: string | null }) {
  const { isCapturing } = useAnalysis();
  const displayed = filterCategory ? rows.filter((r) => r['Predicted Category'] === filterCategory) : rows;

  const getCategoryColor = (cat: string) => {
    switch (cat) {
      case 'Normal':      return 'bg-green-100 text-green-800';
      case 'Suspicious':  return 'bg-yellow-100 text-yellow-800';
      case 'Attack-like': return 'bg-red-100 text-red-800';
      case 'Anomaly':     return 'bg-orange-100 text-orange-800';
      default:            return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="w-full bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mt-4">
      <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-white">
        <h2 className="text-base font-black text-gray-900 uppercase tracking-tight">
          {filterCategory ? `${filterCategory} Flows` : 'Session Flow History'}
        </h2>
        {isCapturing ? (
          <span className="flex items-center gap-2 text-[11px] text-green-600 font-black uppercase tracking-widest">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            Live Updating
          </span>
        ) : (
          <span className="text-[11px] text-gray-400 font-black uppercase tracking-widest">
            Capture Offline
          </span>
        )}
      </div>

      <div className="overflow-x-auto overflow-y-auto max-h-[550px]">
        <table className="w-full min-w-[1100px] table-fixed text-left border-collapse">
          <thead className="bg-gray-50 border-b border-gray-200 sticky top-0 z-10">
            <tr>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Src IP</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Src Port</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Dst IP</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Dst Port</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Label</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest text-right">Category</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white">
            {displayed.length > 0 ? (
              displayed.map((row, i) => (
                <tr key={i} className="hover:bg-blue-50/40 transition-colors">
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-mono font-medium whitespace-nowrap">{row['Src IP'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-mono font-medium whitespace-nowrap">{row['Src Port'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-600 font-mono">{row['Dst IP'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-600 font-mono">{row['Dst Port'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-semibold relative group cursor-pointer">
                    {row['Predicted Label']}
                    <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 hidden group-hover:block z-50 w-64 bg-black text-white text-[11px] p-2 rounded shadow-lg">
                      {LABEL_INFO[row['Predicted Label']] || "No description available"}
                    </div>
                  </td>
                  <td className="px-6 py-3.5 text-right">
                    <span className={`inline-flex px-3 py-1 rounded-full text-[10px] font-bold uppercase ${getCategoryColor(row['Predicted Category'])}`}>
                      {row['Predicted Category']}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} className="px-6 py-24 text-center text-sm text-gray-400 font-black uppercase tracking-[0.3em] bg-white">
                  No network data points recorded
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CategoryTab({ category }: { category: 'normal' | 'suspicious' | 'attack' }) {
  const { result } = useAnalysis();
  if (!result) return null;

  const config = {
    normal:    { title: 'Normal Traffic',    filterKey: 'Normal' as const,    icon: CheckCircle,   color: 'text-green-600',  bgColor: 'bg-green-50' },
    suspicious:{ title: 'Suspicious Traffic',filterKey: 'Suspicious' as const,icon: AlertCircle,   color: 'text-yellow-600', bgColor: 'bg-yellow-50' },
    attack:    { title: 'Attack-like Traffic',filterKey:'Attack-like' as const,icon: AlertTriangle, color: 'text-red-600',    bgColor: 'bg-red-50' },
  }[category];

  const count = result.summary[config.filterKey];

  return (
    <div className="space-y-4 animate-in slide-in-from-bottom-2 duration-500">
      <div className="flex flex-col md:flex-row gap-4 w-full justify-center">
        <div className="flex-1 bg-white rounded-lg shadow-sm border border-gray-200 p-5 text-center">
          <div className="text-[10px] text-gray-400 mb-1 uppercase tracking-widest font-bold">Total {config.filterKey} Flows</div>
          <div className="text-4xl font-black text-gray-900">{count.toLocaleString()}</div>
        </div>
        <div className="flex-1 bg-white rounded-lg shadow-sm border border-gray-200 p-5 text-center">
          <div className="text-[10px] text-gray-400 mb-1 uppercase tracking-widest font-bold">Category Share</div>
          <div className="text-4xl font-black text-gray-900">
            {result.summary.total > 0 ? ((count / result.summary.total) * 100).toFixed(1) : '0'}<span className="text-xl ml-1">%</span>
          </div>
        </div>
      </div>
      <div className={`${config.bgColor} border rounded-lg p-3 flex items-center gap-4`}>
        <config.icon className={`w-8 h-8 ${config.color}`} />
        <div>
          <h2 className={`text-sm font-bold ${config.color}`}>{config.title}</h2>
          <p className="text-[11px] text-gray-500 opacity-80">Analysis of {config.filterKey.toLowerCase()} network behaviors in the session.</p>
        </div>
      </div>
      <ResultsFlowTable rows={result.rows} filterCategory={config.filterKey} />
    </div>
  );
}