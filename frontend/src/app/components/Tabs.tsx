interface Tab {
  id: string;
  label: string;
  color?: string;
}

interface TabsProps {
  tabs: Tab[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
}

export function Tabs({ tabs, activeTab, onTabChange }: TabsProps) {
  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <div className="flex overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`px-6 py-4 font-medium text-sm whitespace-nowrap border-b-2 transition-colors ${
              activeTab === tab.id
                ? `border-${tab.color || 'blue'}-600 text-${tab.color || 'blue'}-600`
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
            style={
              activeTab === tab.id && tab.color
                ? {
                    borderBottomColor: tab.color,
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
  );
}