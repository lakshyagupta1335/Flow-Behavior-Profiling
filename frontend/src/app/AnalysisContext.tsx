import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';

export interface FlowRow {
  'Src IP'?: string;
  'Src Port'?: number | string;
  'Dst IP'?: string;
  'Dst Port'?: number | string;
  'Predicted Label': string;
  'Predicted Category': 'Normal' | 'Misconfigured' | 'Suspicious' | 'Attack-like' | 'Anomaly';
  'Throughput (Mbps)'?: number;
  'Upload (Mbps)'?: number;
  'Download (Mbps)'?: number;
  'Packet Rate (pps)'?: number;
  'Avg Packet Size'?: number;
  'Flow Duration (ms)'?: number;
  'Bytes'?: number;
  'Direction'?: string;
  'Protocol'?: string;
  'Source'?: 'real' | 'synthetic';
  'Client Insights'?: {
  traits: string[];
  beacon_score: number;
  syn: number;
  rst: number;
  ack: number;
  fin: number;
  down_up_ratio?: number;
  transport_protocol?: string;
  service?: string;
  };
}

export interface AnalysisResult {
  summary: {
    Normal: number;
    Misconfigured: number;
    Suspicious: number;
    'Attack-like': number;
    Anomaly: number;
    total: number;
  };
  rows: FlowRow[];
}

export interface NetworkMetricsSummary {
  throughput_mbps: number;
  upload_mbps: number;
  download_mbps: number;
  avg_throughput_mbps: number;
  avg_upload_mbps: number;
  avg_download_mbps: number;

  avg_packet_rate_pps: number;
  avg_packet_size: number;
  avg_flow_duration: number;

  flows: number;
  inbound: number;
  outbound: number;
  balanced: number;
}

interface AnalysisContextValue {
  result: AnalysisResult | null;
  networkMetrics: NetworkMetricsSummary | null;
  statusMsg: string;
  interfaces: string[];
  isCapturing: boolean;
  csvFileName: string | null;
  csvProgress: number;
  uploadCSV: (file: File) => Promise<void>;
  fetchInterfaces: () => void;
  startCapture: (iface: string) => void;
  stopCapture: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);
let socket: Socket;

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [networkMetrics, setNetworkMetrics] = useState<NetworkMetricsSummary | null>(null);
  const [statusMsg, setStatusMsg] = useState('Initialize engine to begin...');
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [csvFileName, setCsvFileName] = useState<string | null>(null);
  const [csvProgress, setCsvProgress] = useState<number>(0);

  useEffect(() => {
    socket = io('http://localhost:5000', {
      transports: ['websocket'],
      reconnectionAttempts: 5
    });

    socket.on('connect', () => {
      socket.emit('stop_capture');
      socket.emit('get_interfaces');
      setIsCapturing(false);
    });

    socket.on('interfaces_list', (list: string[]) => {
      setInterfaces(list);
    });

    socket.on('status_update', (msg: string) => setStatusMsg(msg));

    socket.on('csv_progress', (data) => {setCsvProgress(data.progress);
    setStatusMsg(`Processing ${csvFileName || 'CSV'}... ${data.progress}%`);
    });

    socket.on('csv_done', async (data) => {
      setCsvProgress(100);
      setIsCapturing(false);

      const res = await fetch(
        'http://localhost:5000/csv_rows?page=0'
      );

      const json = await res.json();

      setResult({
        summary: data.summary,
        rows: json.rows
      });

      setStatusMsg('CSV Analysis Complete');
    });

    socket.on('network_metrics_summary', (metrics: NetworkMetricsSummary) => {
      setNetworkMetrics(metrics);
    });

    socket.on('new_flow_batch', (newFlows: FlowRow[]) => {
      setResult(prev => {
        const initial = prev || {
          summary: { Normal: 0, Misconfigured: 0, Suspicious: 0, 'Attack-like': 0, Anomaly: 0, total: 0 },
          rows: []
        };
        const updatedRows = [...newFlows, ...initial.rows].slice(0,1000);
        const updatedSummary = { ...initial.summary };

        newFlows.forEach(flow => {
          const cat = flow['Predicted Category'];
          if (cat in updatedSummary) updatedSummary[cat]++;
          updatedSummary.total++;
        });

        return { ...initial, rows: updatedRows, summary: updatedSummary };
      });
    });

    return () => {
      socket.off('connect');
      socket.off('interfaces_list');
      socket.off('status_update');
      socket.off('network_metrics_summary');
      socket.off('new_flow_batch');
      socket.off('csv_progress');
      socket.off('csv_done');
      socket.disconnect();
    };
  }, []);

  const fetchInterfaces = () => {
    if (socket && socket.connected) {
      socket.emit('get_interfaces');
    } else {
      socket.connect();
    }
  };

  const startCapture = (interfaceName: string) => {
    setResult(null);
    setNetworkMetrics(null); 
    setIsCapturing(true);
    socket.emit('start_capture', { interface: interfaceName });
  };

  const stopCapture = () => {
    setIsCapturing(false);
    socket.emit('stop_capture');
  };

  const uploadCSV = async (file: File) => {
    setIsCapturing(true);
    setResult(null);
    setNetworkMetrics(null);

    setCsvFileName(file.name);
    setCsvProgress(0);

    setStatusMsg(`Uploading ${file.name}...`);

    setResult({
      summary: {
        Normal: 0,
        Misconfigured: 0,
        Suspicious: 0,
        'Attack-like': 0,
        Anomaly: 0,
        total: 0
      },
      rows: []
    });


  const formData = new FormData();
  formData.append('file', file);

  await fetch(
    'http://localhost:5000/upload_csv',
    {
      method: 'POST',
      body: formData
    }
  );
};

  return (
    <AnalysisContext.Provider value={{
      result,
      networkMetrics,
      statusMsg,
      interfaces,
      isCapturing,
      csvFileName,
      csvProgress,
      uploadCSV,
      fetchInterfaces,
      startCapture,
      stopCapture
    }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export const useAnalysis = () => useContext(AnalysisContext)!;