import { useState } from 'react';
import { Upload, FileCheck, AlertCircle, Activity } from 'lucide-react';

interface HomePageProps {
  onAnalysisStart: () => void;
}

export function HomePage({ onAnalysisStart }: HomePageProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      setUploadedFile(files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      setUploadedFile(files[0]);
    }
  };

  const handleAnalyze = () => {
    setIsProcessing(true);
    setTimeout(() => {
      setIsProcessing(false);
      onAnalysisStart();
    }, 2000);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-blue-50 via-white to-purple-50">
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-4xl w-full">
          <div className="text-center mb-12">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Activity className="w-12 h-12 text-blue-600" />
              <h1 className="text-5xl font-bold text-gray-900">Network Flow Behavior</h1>
            </div>
            <p className="text-xl text-gray-600 mb-2">
              Advanced Network Traffic Analysis & Classification
            </p>
            <p className="text-gray-500">
              Upload your network flow dataset to get comprehensive security insights and traffic analysis
            </p>
          </div>

          <div className="bg-white rounded-2xl shadow-xl p-8 mb-8">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">Upload Dataset</h2>

            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-xl p-12 text-center transition-all ${
                isDragging
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-300 bg-gray-50 hover:border-blue-400 hover:bg-blue-50'
              }`}
            >
              {uploadedFile ? (
                <div className="space-y-4">
                  <FileCheck className="w-16 h-16 text-green-600 mx-auto" />
                  <div>
                    <p className="text-lg font-semibold text-gray-900">{uploadedFile.name}</p>
                    <p className="text-sm text-gray-500">
                      {(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB
                    </p>
                  </div>
                  <button
                    onClick={() => setUploadedFile(null)}
                    className="text-sm text-blue-600 hover:text-blue-700 font-medium"
                  >
                    Change file
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="w-16 h-16 text-gray-400 mx-auto" />
                  <div>
                    <p className="text-lg font-semibold text-gray-900 mb-2">
                      Drag and drop your dataset here
                    </p>
                    <p className="text-sm text-gray-500 mb-4">or</p>
                    <label className="inline-flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 cursor-pointer transition-colors">
                      <Upload className="w-5 h-5 mr-2" />
                      Browse Files
                      <input
                        type="file"
                        className="hidden"
                        onChange={handleFileInput}
                        accept=".csv,.pcap,.json,.txt"
                      />
                    </label>
                  </div>
                  <p className="text-xs text-gray-400">
                    Supported formats: CSV, PCAP, JSON, TXT
                  </p>
                </div>
              )}
            </div>

            {uploadedFile && (
              <button
                onClick={handleAnalyze}
                disabled={isProcessing}
                className="w-full mt-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold text-lg hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg hover:shadow-xl"
              >
                {isProcessing ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Analyzing Dataset...
                  </span>
                ) : (
                  'Start Analysis'
                )}
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white rounded-xl p-6 shadow-sm">
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                <FileCheck className="w-6 h-6 text-green-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Upload Dataset</h3>
              <p className="text-sm text-gray-600">
                Upload your network traffic capture file for analysis
              </p>
            </div>

            <div className="bg-white rounded-xl p-6 shadow-sm">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                <Activity className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Automatic Analysis</h3>
              <p className="text-sm text-gray-600">
                ML-powered classification identifies traffic patterns
              </p>
            </div>

            <div className="bg-white rounded-xl p-6 shadow-sm">
              <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                <AlertCircle className="w-6 h-6 text-purple-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Security Insights</h3>
              <p className="text-sm text-gray-600">
                Get detailed reports on threats and anomalies
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}