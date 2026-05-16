import { useState } from 'react';
import { Dashboard } from './components/Dashboard';
import { Navbar } from './components/Navbar';
import { AnalysisProvider } from './AnalysisContext';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <AnalysisProvider>
      <div className="size-full flex flex-col">
        <Navbar
          activeTab={activeTab}
          onTabChange={setActiveTab}
          onHomeClick={() => setActiveTab('overview')}
        />
        <div className="flex-1 overflow-auto">
          <Dashboard activeTab={activeTab} />
        </div>
      </div>
    </AnalysisProvider>
  );
}