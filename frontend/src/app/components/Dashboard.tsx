import React, { useState, useEffect } from 'react';
import {
  CheckCircle, AlertCircle, AlertTriangle, Loader2,
  RefreshCw, Play, Square, ChevronRight, HelpCircle, ShieldCheck,
  Upload,FileText
} from 'lucide-react';
// @ts-ignore
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { useAnalysis, FlowRow } from '../AnalysisContext';

import { LiveMetricsPanel } from './LiveMetricsPanel';
import { TopTalkersSankey } from './TopTalkersSankey';

const LABEL_INFO: Record<string, string> = {
    "BENIGN":
        "Traffic shows normal behavior: standard ports (80/443/53), stable packet size, and no abnormal rate spikes.",
    "Dead Service":
        "The client attempted connection, but the host immediately dropped or rejected the transaction with an RST flag indicator.",
    "TCP Handshake Anomaly":
        "Observed an abnormal volume of half-open connection initialization flags lacking valid ACK handshakes.",
    "Keep Alive Timeout":
        "Connection remained open without passing payload bytes, triggering an idle execution threshold timeout.",
    "Packet Size Anomaly":
        "Flow frame lengths fall radically outside expected structural payload distribution baselines.",
    "DDoS":
        "High traffic volume detected with large packet rates, low idle time, and continuous flow bursts indicating possible bandwidth flooding.",
    "DoS Hulk":
        "Large packet sizes combined with high request frequency and short flow intervals suggest HTTP flood attack behavior.",
    "DoS Hulk - Attempted":
        "Elevated HTTP request activity observed, but traffic volume and flow persistence remain insufficient for a confirmed HTTP flood attack.",
    "DoS GoldenEye":
        "Persistent connections with medium packet sizes and high flow duration indicate slow HTTP exhaustion attack.",
    "DoS GoldenEye - Attempted":
        "Partial pattern of slow HTTP attack with incomplete connection saturation and inconsistent flow duration.",
    "DoS Slowloris":
        "Numerous long-lived connections with very low data transfer rates indicate attempts to exhaust server connection resources.",
    "DoS Slowloris - Attempted":
        "A limited number of slow persistent connections were detected, but connection counts and duration are insufficient for a full Slowloris attack.",
    "DoS Slowhttptest":
        "Slow and fragmented HTTP requests with prolonged connection holding behavior suggest Slow HTTP test attack activity.",
    "DoS Slowhttptest - Attempted":
        "Evidence of delayed HTTP request transmission exists, but resource exhaustion patterns remain incomplete and inconsistent.",
    "Portscan":
        "Very small packet sizes with extremely high forward packet rate indicate automated port scanning activity.",
    "Infiltration - Portscan":
        "Port scanning combined with irregular SYN/ACK patterns and elevated packet frequency suggesting stealth probing.",
    "Infiltration":
        "Irregular internal network traffic with unusual port usage and abnormal flow direction patterns.",
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
    "Botnet":
        "Repeated outbound communication patterns with consistent packet intervals and external IP contact behavior.",
    "Botnet - Attempted":
        "Suspicious periodic traffic to external hosts without stable command-and-control confirmation.",
    "Heartbleed":
        "Large response packets with high memory-like variance and abnormal TLS heartbeat behavior detected.",
    "Web Attack - Brute Force":
        "Repeated web authentication requests with high login frequency and multiple failed credential attempts indicate password guessing activity.",
    "Web Attack - Brute Force - Attempted":
        "Multiple web login attempts were observed, but authentication request volume and persistence remain below confirmed brute-force thresholds.",
    "Web Attack - XSS":
        "HTTP requests contain suspicious script-like payloads and encoded input patterns consistent with cross-site scripting attempts.",
    "Web Attack - XSS - Attempted":
        "Potential script injection patterns were detected in web requests, but payload execution indicators are incomplete or inconclusive.",
    "Web Attack - SQL Injection":
        "Malicious query patterns, database-oriented keywords, and abnormal request parameters suggest SQL injection activity.",
    "Web Attack - SQL Injection - Attempted":
        "Requests contain partial SQL manipulation patterns, but exploitation indicators are insufficient for confirmed database injection.",
    "Anomaly":
        "Statistical deviation detected in packet size, flow rate, or timing compared to normal baseline traffic.",
    "Attack-like":
        "Traffic shows suspicious patterns but does not match any specific known attack signature.",
    "Unknown":
        "Insufficient feature confidence or incomplete flow data prevents classification."
};

export function Dashboard({ activeTab }: { activeTab: string }) {
  const {
    statusMsg, interfaces, fetchInterfaces,
    startCapture, stopCapture, isCapturing, result,
    csvFileName, csvProgress, uploadCSV
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

            {!isCapturing && (
              <>
                <label className="flex items-center gap-2 px-3 py-1 bg-gray-800 text-white rounded hover:bg-gray-700 transition-all shadow-sm cursor-pointer">
                  <Upload className="w-3 h-3" />
                  <span className="text-[10px] font-black uppercase tracking-widest">
                    Upload CSV
                  </span>

                  <input
                    type="file"
                    accept=".csv"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) {
                        uploadCSV(f);
                        setShowPicker(false);
                      }
                      e.target.value = '';
                    }}/>
                </label>
              </>
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
              {csvFileName && csvProgress < 100
                ? `ANALYZING ${csvFileName} (${csvProgress}%)`
                : isCapturing
                  ? `Monitoring incoming flows on ${selectedIface}...`
                  : 'Engine idle. Click Start Session to begin.'
              }
            </p>
            {csvFileName && csvProgress < 100 && (
              <div className="w-80 mt-4 bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${csvProgress}%` }}
                />
              </div>
            )}
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

            {activeTab === 'metrics'        && <MetricsTab />}
            {activeTab === 'overview'       && <OverviewTab />}
            {activeTab === 'normal'         && <CategoryTab category="normal" />}
            {activeTab === 'misconfigured'  && <CategoryTab category="misconfigured" />}
            {activeTab === 'suspicious'     && <CategoryTab category="suspicious" />}
            {activeTab === 'attack'         && <CategoryTab category="attack" />}
          </div>
        )}
      </div>
    </div>
  );
}

function MetricsTab() {
  return (
    <div className="space-y-4 animate-in fade-in duration-500">
      <LiveMetricsPanel />
      <TopTalkersSankey />
    </div>
  );
}

function OverviewTab() {
  const { result, isCapturing } = useAnalysis();
  const [report, setReport] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  if (!result) return null;
  const { summary } = result;

  const generateReport = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch('http://localhost:5000/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ summary, rows: result.rows })
      });
      const data = await res.json();
      setReport(data.report);
    } catch (error) {
      console.error("Failed to generate report", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadPDF = async () => {
    try {
      setIsDownloading(true);
      const element = document.getElementById('ai-report-content');
      if (!element) return;

      const html2pdfModule = await import('html2pdf.js');
      const html2pdf = html2pdfModule.default || html2pdfModule;

      const opt = {
        margin: [0.5, 0.5, 0.5, 0.5],
        filename: 'SOC_Session_Analysis.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: {
          scale: 2,
          useCORS: true,
          allowTaint: true,
          logging: false,
          scrollY: 0,
          scrollX: 0,
          windowWidth: 1000,
          backgroundColor: '#ffffff',
          onclone: (clonedDoc: Document) => {
            const styleTags = clonedDoc.querySelectorAll('style, link[rel="stylesheet"]');
            styleTags.forEach(tag => tag.remove());

            const style = clonedDoc.createElement('style');
            style.textContent = `
              * { box-sizing: border-box !important; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
              body { font-family: Arial, Helvetica, DejaVu Sans, Liberation Sans, sans-serif !important; font-size: 13px !important; color: #111827 !important; background-color: #ffffff !important; margin: 0 !important; padding: 0 !important; }
              #ai-report-content { background-color: #ffffff !important; color: #111827 !important; padding: 32px !important; width: 100% !important; }
              table { width: 100% !important; border-collapse: collapse !important; border-spacing: 0 !important; table-layout: fixed !important; margin: 16px 0 !important; border: 1px solid #d1d5db !important; background-color: #ffffff !important; }
              thead { background-color: #eef2ff !important; }
              th { padding: 10px 14px !important; font-size: 11px !important; font-weight: 900 !important; color: #4f46e5 !important; text-transform: uppercase !important; letter-spacing: 0.06em !important; border-bottom: 2px solid #4f46e5 !important; border-right: 1px solid #d1d5db !important; text-align: left !important; white-space: nowrap !important; overflow: hidden !important; background-color: #eef2ff !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              th:last-child { border-right: none !important; }
              td { padding: 9px 14px !important; font-size: 12px !important; border-bottom: 1px solid #e5e7eb !important; border-right: 1px solid #e5e7eb !important; text-align: left !important; word-break: break-word !important; color: #374151 !important; background-color: #ffffff !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              td:last-child { border-right: none !important; }
              tr:nth-child(even) td { background-color: #f9fafb !important; }
              h1 { font-size: 15px !important; font-weight: 900 !important; color: #111827 !important; margin: 24px 0 10px !important; text-transform: uppercase !important; border-left: 4px solid #4f46e5 !important; padding-left: 10px !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              h2 { font-size: 13px !important; font-weight: 900 !important; color: #4f46e5 !important; margin: 20px 0 8px !important; text-transform: uppercase !important; border-bottom: 1px solid #e5e7eb !important; padding-bottom: 4px !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              h3 { font-size: 12px !important; font-weight: 700 !important; color: #374151 !important; margin: 12px 0 6px !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              p { font-size: 12px !important; color: #4b5563 !important; line-height: 1.7 !important; margin-bottom: 10px !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              ul { padding-left: 18px !important; margin-bottom: 14px !important; }
              li { font-size: 12px !important; color: #4b5563 !important; margin-bottom: 4px !important; line-height: 1.6 !important; font-family: Arial, Helvetica, DejaVu Sans, sans-serif !important; }
              strong { font-weight: 800 !important; color: #111827 !important; }
            `;
            clonedDoc.head.appendChild(style);

            const svgs = clonedDoc.querySelectorAll('svg');
            svgs.forEach((svg) => {
              if (!svg.getAttribute('width'))  svg.setAttribute('width',  '20');
              if (!svg.getAttribute('height')) svg.setAttribute('height', '20');
            });
          }
        },
        jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
      };

      await html2pdf().set(opt).from(element).toContainer().toCanvas().toImg().toPdf().save();
    } catch (error) {
      console.error("PDF Export Error:", error);
      alert("Failed to export PDF. Check developer console.");
    } finally {
      setIsDownloading(false);
    }
  };

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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <CategoryCountCard label="Normal" value={summary.Normal} icon={CheckCircle}
          borderColor="border-green-200" iconBg="bg-green-50" iconColor="text-green-600" />
        <CategoryCountCard label="Misconfigured" value={summary.Misconfigured || 0} icon={HelpCircle}
          borderColor="border-blue-200" iconBg="bg-blue-50" iconColor="text-blue-600" />
        <CategoryCountCard label="Suspicious" value={summary.Suspicious} icon={AlertCircle}
          borderColor="border-yellow-200" iconBg="bg-yellow-50" iconColor="text-yellow-600" />
        <CategoryCountCard label="Attack-like" value={summary['Attack-like']} icon={AlertTriangle}
          borderColor="border-red-200" iconBg="bg-red-50" iconColor="text-red-600" />
      </div>

      
      {!isCapturing && summary.total > 0 && (
        <div className="flex justify-end mt-4 mb-4">
          <button
            onClick={generateReport}
            disabled={isGenerating}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-indigo-400 transition-all font-bold text-sm shadow-md"
          >
            {isGenerating ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            {isGenerating ? "Analyzing Flow Data..." : "Generate AI SOC Report"}
          </button>
        </div>
      )}

      
      {report && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-[100] p-4">
          <div className="bg-white border border-gray-200 rounded-xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-xl">

            <div className="p-5 border-b border-gray-200 flex justify-between items-center bg-white rounded-t-xl">
              <div className="flex items-center gap-3">
                <svg className="w-6 h-6 text-indigo-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                  <polyline points="10 9 9 9 8 9" />
                </svg>
                <div>
                  <h2 className="text-base font-black text-gray-900 uppercase tracking-tight">Network Behavior Analysis Report</h2>
                  <p className="text-[10px] text-gray-400 font-bold uppercase tracking-widest mt-0.5">SOC Session Summary</p>
                </div>
              </div>
              <button
                onClick={() => setReport(null)}
                disabled={isDownloading}
                className="text-gray-400 hover:text-gray-600 disabled:opacity-50 transition-colors text-2xl leading-none font-light"
              >
                &times;
              </button>
            </div>

            <div className="p-8 overflow-y-auto overscroll-none bg-gray-50">
              <div id="ai-report-content" style={{ backgroundColor: '#ffffff', color: '#111827', padding: '32px', borderRadius: '8px', border: '1px solid #e5e7eb', fontFamily: 'Arial, Helvetica, DejaVu Sans, Liberation Sans, sans-serif' }}>
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    table: ({node, ...props}) => (
                      <div style={{ overflowX: 'auto', margin: '1.25rem 0', width: '100%' }}>
                        <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', backgroundColor: '#ffffff', border: '1px solid #e5e7eb', tableLayout: 'auto' }} {...props} />
                      </div>
                    ),
                    thead: ({node, ...props}) => <thead style={{ backgroundColor: '#eef2ff', borderBottom: '2px solid #4f46e5' }} {...props} />,
                    th: ({node, ...props}) => <th style={{ padding: '10px 16px', fontSize: '0.68rem', fontWeight: 900, color: '#4f46e5', textTransform: 'uppercase', letterSpacing: '0.08em', whiteSpace: 'nowrap', borderRight: '1px solid #e5e7eb', fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    td: ({node, ...props}) => {
                      const children = (props as any).children;
                      const text = typeof children === 'string' ? children : Array.isArray(children) ? children.join('') : '';

                      let cellColor = '#374151';
                      let cellBg = 'transparent';
                      let cellWeight: string | number = 'normal';
                      if (text === 'High' || text === 'Critical')  { cellColor = '#dc2626'; cellBg = '#fef2f2'; cellWeight = 700; }
                      else if (text === 'Medium')                  { cellColor = '#d97706'; cellBg = '#fffbeb'; cellWeight = 700; }
                      else if (text === 'Low')                     { cellColor = '#16a34a'; cellBg = '#f0fdf4'; cellWeight = 700; }
                      else if (text === 'Normal')                  { cellColor = '#16a34a'; cellBg = '#f0fdf4'; cellWeight = 700; }
                      else if (text === 'Attack-like')             { cellColor = '#dc2626'; cellBg = '#fef2f2'; cellWeight = 700; }
                      else if (text === 'Suspicious')              { cellColor = '#d97706'; cellBg = '#fffbeb'; cellWeight = 700; }

                      return <td style={{ padding: '10px 16px', fontSize: '0.8rem', borderBottom: '1px solid #f3f4f6', borderRight: '1px solid #f3f4f6', color: cellColor, backgroundColor: cellBg, fontWeight: cellWeight, fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />;
                    },
                    h1: ({node, ...props}) => <h1 style={{ fontSize: '1.1rem', fontWeight: 900, color: '#111827', marginTop: '2rem', marginBottom: '0.75rem', textTransform: 'uppercase', borderLeft: '4px solid #4f46e5', paddingLeft: '12px', fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    h2: ({node, ...props}) => <h2 style={{ fontSize: '0.85rem', fontWeight: 900, color: '#4f46e5', marginTop: '1.75rem', marginBottom: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    h3: ({node, ...props}) => <h3 style={{ fontSize: '0.8rem', fontWeight: 700, color: '#374151', marginTop: '1rem', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    p: ({node, ...props}) => <p style={{ marginBottom: '0.85rem', lineHeight: 1.75, fontSize: '0.85rem', color: '#4b5563', fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    ul: ({node, ...props}) => <ul style={{ paddingLeft: '1.25rem', marginBottom: '1.25rem', listStyleType: 'disc' }} {...props} />,
                    li: ({node, ...props}) => <li style={{ marginBottom: '0.35rem', fontSize: '0.85rem', color: '#4b5563', lineHeight: 1.6, fontFamily: 'Arial, Helvetica, sans-serif' }} {...props} />,
                    strong: ({node, ...props}) => <strong style={{ fontWeight: 800, color: '#111827' }} {...props} />
                  }}
                >
                  {report}
                </ReactMarkdown>
              </div>
            </div>

            <div className="p-4 border-t border-gray-200 flex justify-end gap-3 bg-white rounded-b-xl">
              <button
                onClick={() => setReport(null)}
                disabled={isDownloading}
                className="px-5 py-2 bg-gray-100 hover:bg-gray-200 disabled:opacity-50 rounded-md text-gray-600 font-black text-xs uppercase tracking-widest transition-colors"
              >
                Close
              </button>
              <button
                onClick={downloadPDF}
                disabled={isDownloading}
                className="flex items-center gap-2 px-5 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 rounded-md text-white font-black text-xs uppercase tracking-widest transition-colors shadow-sm"
              >
                {isDownloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
                {isDownloading ? "Generating PDF..." : "Export as PDF"}
              </button>
            </div>

          </div>
        </div>
      )}
      

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
      <div className="text-3xl font-black text-gray-900 leading-tight">{value?.toLocaleString() || '0'}</div>
      <div className="text-[10px] text-gray-400 uppercase tracking-widest font-bold">{label}</div>
    </div>
  );
}

function ResultsFlowTable({ rows, filterCategory }: { rows: FlowRow[]; filterCategory: string | null }) {
  const { isCapturing } = useAnalysis();
  const [openTooltip, setOpenTooltip] = useState<number | null>(null);
  
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      setOpenTooltip(null);
    };

    document.addEventListener("click", handleClickOutside);
    return () => {
      document.removeEventListener("click", handleClickOutside);
    };
  }, []);
  
  const displayed = filterCategory ? rows.filter((r) => r['Predicted Category'] === filterCategory) : rows;

  const getClientInsightLabel = (
    ci?: FlowRow['Client Insights'],
    category?: FlowRow['Predicted Category']
  ) => {
  if (!ci || !ci.traits) return "Normal activity";

  const t = ci.traits;

  const has = (keyword: string) =>
    t.some(x => x.toLowerCase().includes(keyword.toLowerCase()));

  
  if (category === "Attack-like") {
    if (has("Handshake anomaly"))
      return "Unusual connection attempts";

    if (has("Unstable connection pattern"))
      return "Unstable connection behavior";

    if (has("Automated periodic behavior"))
      return "Regular automated behavior detected";

    if (has("Extreme download-heavy flow"))
      return "Abnormally high download activity";

    if (has("Extreme upload-heavy flow"))
      return "Abnormally high upload activity";

    return "Attack-like Behavior";
  }

  
  if (category === "Suspicious") {
    if (has("Automated periodic behavior"))
      return "Regular automated activity";

    if (has("Handshake anomaly"))
      return "Repeated connection attempts";

    if (has("Unstable connection pattern"))
      return "Unusual connection instability";

    if (has("Extreme download-heavy flow"))
      return "Heavy download activity";

    if (has("Extreme upload-heavy flow"))
      return "Heavy upload activity";

    return "Unusual network activity";
  }

  
  if (category === "Misconfigured") {
    if (has("Unstable connection pattern"))
      return "Connection is unstable";

    if (has("Handshake anomaly"))
      return "Connection not fully established";

    if (has("Extreme download-heavy flow"))
      return "Traffic pattern may be misconfigured";

    if (has("Extreme upload-heavy flow"))
      return "Upload traffic may be misconfigured";

    return "Configuration Issue";
  }

  return "Normal activity";
  };

  const getCategoryColor = (cat: string) => {
    switch (cat) {
      case 'Normal':      return 'bg-green-100 text-green-800'; 
      case 'Misconfigured':return 'bg-blue-100 text-blue-800';  
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
        <table className="w-full table-fixed text-left border-collapse">
          <thead className="bg-gray-50 border-b border-gray-200 sticky top-0 z-10">
            <tr>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest ">Src IP</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Src Port</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Dst IP</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Dst Port</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest ">Protocol</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Label</th>
              <th className="px-6 py-4 text-[11px] font-black text-gray-500 uppercase tracking-widest">Category</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white">
            {displayed.length > 0 ? (
              displayed.map((row, i) => (
                <tr key={i} className="hover:bg-blue-50/40 transition-colors">
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-mono">{row['Src IP'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-mono">{row['Src Port'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-600 font-mono">{row['Dst IP'] ?? 'N/A'}</td>
                  <td className="px-6 py-3.5 text-sm text-gray-600 font-mono">{row['Dst Port'] ?? 'N/A'}</td>
              
                  <td className="px-6 py-3.5 text-sm text-gray-700 font-mono">
                    <div className="flex items-center gap-1 group relative w-fit">
                      <span>{row['Protocol'] ?? 'N/A'}</span>

                      <HelpCircle className="w-3.5 h-3.5 text-gray-400 cursor-pointer hover:text-gray-600"
                       onClick={(e) => {e.stopPropagation(); setOpenTooltip(openTooltip === i ? null : i);}} />

                      <div className={`absolute left-full ml-2 top-1/2 -translate-y-1/4 w-56 max-h-64 overflow-y-auto bg-slate-900/95 backdrop-blur-md text-slate-200 text-[11px] p-3 rounded-lg shadow-2xl border border-slate-700 z-[9999] transition-opacity duration-150
                      ${
                        openTooltip === i
                        ? "opacity-100 pointer-events-auto"
                        : "opacity-0 pointer-events-none group-hover:opacity-100"
                      }
                      `}
                      >
                      <div className="font-bold text-lg text-white mb-2 border-b border-slate-700 pb-1">Flow Behavior</div>

                      <div className="mb-2 text-slate-300 leading-snug">
                        <span className="text-white font-extrabold text-[14px]">{getClientInsightLabel(row['Client Insights'], row['Predicted Category'])}</span>
                      </div>

                      <div className="border-t border-slate-700 my-2" />
                         <div className="space-y-1 text-slate-300">
                          <div>
                            <span className="text-green-300 font-bold text-[12px]">Traits:</span>{" "}
                            {(row['Client Insights']?.traits || []).join(", ") || "None"}
                          </div>
                          <div>
                            <span className="text-sky-300 font-bold text-[12px]">Application Layer:</span>{" "}
                            {row['Client Insights']?.service || "N/A"}
                          </div>
                          <div>
                            <span className="text-cyan-400 font-bold text-[12px]">Transport Protocol:</span>{" "}
                            {row['Client Insights']?.transport_protocol || "N/A"}
                          </div>
                          <div>
                            <span className="text-pink-300 font-bold text-[12px]">IAT variability:</span>{" "}
                            {row['Client Insights']?.beacon_score ?? 0}
                          </div>
                          <div>
                            <span className="text-yellow-300 font-bold text-[12px]">Down/Up:</span>{" "}
                            {row['Client Insights']?.down_up_ratio ?? 0}
                          </div>
                          <div>
                            <span className="text-red-100 font-bold text-[12px]">SYN:</span>{" "}
                            {row['Client Insights']?.syn ?? 0} |
                            <span className="text-red-100 font-bold ml-1 text-[12px]">ACK:</span> {row['Client Insights']?.ack ?? 0}
                          </div>
                          <div>
                            <span className="text-orange-300 font-bold text-[12px]">RST:</span>{" "}
                            {row['Client Insights']?.rst ?? 0} |
                            <span className="text-orange-300 font-bold ml-1 text-[12px]">FIN:</span> {row['Client Insights']?.fin ?? 0}
                          </div>
                        </div>
                      </div>
                    </div>
                  </td>

                  <td className="px-6 py-3.5 text-sm text-gray-700 font-semibold relative group cursor-pointer">
                    {row['Predicted Label']}
                    <div className="absolute left-full -ml-2 top-1/2 -translate-x-[20%] -translate-y-1/2 opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-150 w-44 max-h-60 overflow-y-auto bg-black text-white text-[11px] p-2 rounded shadow-lg z-[9999] text-[12px]">
                      {LABEL_INFO[row['Predicted Label']] || "No description available"}
                    </div>
                  </td>

                  <td className="px-6 py-3.5 text-left">
                    <span className={`inline-flex px-3 py-1 rounded-full text-[10px] font-bold uppercase ${getCategoryColor(row['Predicted Category'])}`}>
                      {row['Predicted Category']}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} className="px-6 py-24 text-center text-sm text-gray-400 font-black uppercase tracking-[0.3em] bg-white">
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

function CategoryTab({ category }: { category: 'normal' | 'misconfigured' | 'suspicious' | 'attack' }) {
  const { result } = useAnalysis();
  if (!result) return null;

  const config = {
    normal:       { title: 'Normal Traffic',          filterKey: 'Normal' as const,        icon: CheckCircle,   color: 'text-green-600',  bgColor: 'bg-green-50' },
    misconfigured:{ title: 'Configuration Anomalies', filterKey: 'Misconfigured' as const, icon: HelpCircle,    color: 'text-blue-600',   bgColor: 'bg-blue-50' },
    suspicious:   { title: 'Suspicious Traffic',      filterKey: 'Suspicious' as const,    icon: AlertCircle,   color: 'text-yellow-600', bgColor: 'bg-yellow-50' },
    attack:       { title: 'Attack-like Traffic',     filterKey: 'Attack-like' as const,   icon: AlertTriangle, color: 'text-red-600',    bgColor: 'bg-red-50' },
  }[category];

  const count = result.summary[config.filterKey] || 0;

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