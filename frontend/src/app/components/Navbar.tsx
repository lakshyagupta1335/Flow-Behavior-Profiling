import { Activity } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  onHomeClick: () => void;
}

export function Navbar({ activeTab, onTabChange, onHomeClick }: NavbarProps) {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'normal', label: 'Normal', color: '#10b981' },
    { id: 'suspicious', label: 'Suspicious', color: '#eab308' },
    { id: 'attack', label: 'Attack-like', color: '#ef4444' }
  ];

  return (
    <nav className="bg-white border-b border-gray-200 shadow-sm">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          <button
            onClick={onHomeClick}
            className="flex items-center gap-2 hover:opacity-80 transition-opacity"
          >
            <Activity className="w-6 h-6 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">Network Flow Behavior</span>
          </button>

          <div className="flex gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
                style={
                  activeTab === tab.id && tab.color
                    ? {
                        backgroundColor: `${tab.color}20`,
                        color: tab.color
                      }
                    : undefined
                }
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </nav>
  );
}