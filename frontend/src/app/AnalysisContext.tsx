import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';

export interface FlowRow {
  'Src IP'?: string;
  'Src Port'?: number | string;
  'Dst IP'?: string;
  'Dst Port'?: number | string;
  'Predicted Label': string;
  'Predicted Category': 'Normal' | 'Suspicious' | 'Attack-like' | 'Anomaly';
}

export interface AnalysisResult {
  summary: { Normal: number; Suspicious: number; 'Attack-like': number; Anomaly: number; total: number; };
  rows: FlowRow[];
}

interface AnalysisContextValue {
  result: AnalysisResult | null;
  statusMsg: string;
  interfaces: string[];
  isCapturing: boolean;
  fetchInterfaces: () => void;
  startCapture: (iface: string) => void;
  stopCapture: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);
let socket: Socket;

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [statusMsg, setStatusMsg] = useState('Initialize engine to begin...');
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [isCapturing, setIsCapturing] = useState(false);

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

    socket.on('new_flow_batch', (newFlows: FlowRow[]) => {
      setResult(prev => {
        const initial = prev || { summary: { Normal: 0, Suspicious: 0, 'Attack-like': 0, Anomaly: 0, total: 0 }, rows: [] };
        const updatedRows = [...newFlows, ...initial.rows].slice(0, 1000);
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
      socket.off('new_flow_batch');
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
    setIsCapturing(true);
    socket.emit('start_capture', { interface: interfaceName });
  };

  const stopCapture = () => {
    setIsCapturing(false);
    socket.emit('stop_capture');
  };

  return (
    <AnalysisContext.Provider value={{
      result, statusMsg, interfaces, isCapturing,
      fetchInterfaces, startCapture, stopCapture
    }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export const useAnalysis = () => useContext(AnalysisContext)!;