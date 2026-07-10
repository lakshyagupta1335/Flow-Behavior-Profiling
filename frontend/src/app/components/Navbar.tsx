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
    { id: 'misconfigured', label: 'Misconfigured', color: '#2563eb' }, 
    { id: 'suspicious', label: 'Suspicious', color: '#eab308' },
    { id: 'attack', label: 'Attack-like', color: '#ef4444' }
  ];

  const metricsTab = { 
    id: 'metrics', 
    label: 'Flow Analytics', 
    color: '#3b82ff', 
    style: { 
      border: '2px solid #bbddff', 
      fontSize: '16px', 
      fontWeight: '600',
      paddingLeft: '20px',
      paddingRight: '20px'
    } 
  };

  return (
    <nav className="bg-white border-b border-gray-200 shadow-sm relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16 relative">
          <button
            onClick={onHomeClick}
            className="flex items-center gap-2 hover:opacity-80 transition-opacity"
          >
            <Activity className="w-6 h-6 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">Flow Behavior Profiling</span>
          </button>

          
          <div className="flex gap-1">
            <button
              onClick={() => onTabChange(metricsTab.id)}
              className={`py-2 rounded-lg transition-colors ${
                activeTab === metricsTab.id
                  ? 'text-gray-900'
                  : 'text-gray-600 hover:bg-gray-200'
              }`}
              style={{
                ...metricsTab.style,
                ...(activeTab === metricsTab.id && metricsTab.color
                  ? {
                      backgroundColor: `${metricsTab.color}20`,
                      borderColor: metricsTab.color
                    }
                  : {
                      borderColor: '#E5E7EB'
                    })
              }}
            >
              {metricsTab.label}
            </button>
          </div>

          
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