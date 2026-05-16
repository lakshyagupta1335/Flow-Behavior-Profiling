import { Github, Mail, FileText } from 'lucide-react';

export function Footer() {
  return (
    <footer className="bg-gray-900 text-gray-300 mt-auto">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="text-lg font-semibold text-white mb-3">About</h3>
            <p className="text-sm text-gray-400">
              Network Flow Behavior is an advanced traffic analysis platform that uses machine learning
              to classify and identify network flows in real-time. Upload your network traffic dataset
              to get comprehensive insights and security analysis.
            </p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-white mb-3">Features</h3>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>• Real-time flow classification</li>
              <li>• Attack detection & analysis</li>
              <li>• Misconfiguration identification</li>
              <li>• Comprehensive traffic visualization</li>
              <li>• Export and reporting capabilities</li>
            </ul>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-white mb-3">Resources</h3>
            <div className="space-y-3">
              <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors">
                <FileText className="w-4 h-4" />
                Documentation
              </a>
              <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors">
                <Github className="w-4 h-4" />
                GitHub Repository
              </a>
              <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors">
                <Mail className="w-4 h-4" />
                Contact Support
              </a>
            </div>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-gray-800 text-center text-sm text-gray-500">
          <p>&copy; {new Date().getFullYear()} Network Flow Behavior. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}