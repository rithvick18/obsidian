import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Cpu, 
  Sliders, 
  BookOpen, 
  UserCheck, 
  BrainCircuit, 
  Globe, 
  Terminal, 
  Bell, 
  CheckCircle, 
  Users,
  Activity,
  Menu,
  X,
  Sun,
  Moon
} from 'lucide-react';
import { ActiveTab } from './types';

// Import our custom views
import ExecutiveView from './components/ExecutiveView';
import QuantumView from './components/QuantumView';
import IncidentsView from './components/IncidentsView';
import AnalyticsView from './components/AnalyticsView';
import RiskView from './components/RiskView';
import CopilotView from './components/CopilotView';
import MapView from './components/MapView';
import SessionsView from './components/SessionsView';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('executive');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('obsidian-theme');
    return (saved === 'light' || saved === 'dark') ? saved : 'dark';
  });
  const [notifications, setNotifications] = useState([
    { id: 1, text: 'New anomalous travel alert for Arjun Vardhan', read: false },
    { id: 2, text: 'Quantum subnet ML-KEM synchronization complete', read: false },
  ]);
  const [showNotifications, setShowNotifications] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'light') {
      root.classList.add('light');
    } else {
      root.classList.remove('light');
    }
    localStorage.setItem('obsidian-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const navigationItems = [
    { id: 'executive', label: 'Executive Dashboard', icon: Shield },
    { id: 'quantum', label: 'Quantum Center', icon: Cpu },
    { id: 'incidents', label: 'Incident Triage', icon: Sliders },
    { id: 'analytics', label: 'Security Analytics', icon: BookOpen },
    { id: 'risk', label: 'User Risk Profiles', icon: UserCheck },
    { id: 'copilot', label: 'AI Copilot Chat', icon: BrainCircuit },
    { id: 'map', label: 'Live Attack Map', icon: Globe },
    { id: 'sessions', label: 'Privileged Sessions', icon: Terminal },
  ] as const;

  const renderActiveView = () => {
    switch (activeTab) {
      case 'executive':
        return <ExecutiveView />;
      case 'quantum':
        return <QuantumView />;
      case 'incidents':
        return <IncidentsView />;
      case 'analytics':
        return <AnalyticsView />;
      case 'risk':
        return <RiskView />;
      case 'copilot':
        return <CopilotView />;
      case 'map':
        return <MapView />;
      case 'sessions':
        return <SessionsView />;
      default:
        return <ExecutiveView />;
    }
  };

  const getBreadcrumbLabel = () => {
    const matched = navigationItems.find(item => item.id === activeTab);
    return matched ? matched.label : 'Dashboard';
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  const handleClearNotifications = () => {
    setNotifications([]);
    setShowNotifications(false);
  };

  return (
    <div className="min-h-screen bg-bg-base text-text-primary font-sans flex flex-col md:flex-row overflow-x-hidden antialiased selection:bg-primary selection:text-on-primary">
      
      {/* Mobile Top Navigation Header */}
      <div className="md:hidden flex items-center justify-between p-4 bg-bg-sidebar border-b border-outline-variant/60 z-30 w-full">
        <div className="flex items-center gap-2">
          <Shield className="text-primary" size={24} />
          <span className="font-display-lg text-lg font-bold tracking-tight text-on-surface">Obsidian XDR</span>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={toggleTheme} 
            className="p-2 text-on-surface-variant hover:text-on-surface transition-colors"
            title="Toggle theme"
          >
            {theme === 'light' ? <Moon size={20} /> : <Sun size={20} />}
          </button>
          <button 
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} 
            className="p-2 text-on-surface-variant hover:text-on-surface"
          >
            {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      {/* Sidebar Navigation Panel (Desktop / Mobile Overlay) */}
      <aside className={`
        fixed md:static inset-y-0 left-0 z-40 w-64 bg-bg-sidebar border-r border-outline-variant/60 flex flex-col justify-between transition-transform duration-300 transform
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
      `}>
        <div>
          {/* Logo Brand Head */}
          <div className="p-6 border-b border-outline-variant/40 flex items-center gap-3">
            <Shield className="text-primary glow-cyan rounded-full p-0.5" size={28} />
            <div>
              <span className="font-display-lg text-lg font-black tracking-wider text-on-surface">OBSIDIAN</span>
              <span className="text-[9px] bg-primary/20 text-primary border border-primary/40 font-bold px-1.5 py-0.2 rounded ml-1.5 uppercase tracking-widest">XDR</span>
            </div>
          </div>

          {/* Navigation Links list */}
          <nav className="p-4 space-y-1.5">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActiveTab(item.id);
                    setIsMobileMenuOpen(false);
                  }}
                  className={`
                    w-full py-2.5 px-3.5 rounded-lg flex items-center gap-3.5 text-sm font-medium transition-all cursor-pointer group relative
                    ${isActive 
                      ? 'bg-primary/10 text-on-surface font-semibold border-l-2 border-primary' 
                      : 'text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high/20 border-l-2 border-transparent'
                    }
                  `}
                >
                  <Icon 
                    size={18} 
                    className={isActive ? 'text-primary' : 'text-on-surface-variant group-hover:text-primary transition-colors'} 
                  />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer Details */}
        <div className="p-4 border-t border-outline-variant/40 bg-surface-container-lowest/20">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center font-bold text-xs text-primary">
              OP
            </div>
            <div>
              <p className="text-xs font-bold text-on-surface font-sans">SOC_Operator_04</p>
              <p className="text-[10px] text-on-surface-variant font-mono uppercase font-semibold">Tier-3 Analyst</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area Wrapper */}
      <main className="flex-1 flex flex-col min-w-0 min-h-screen relative">
        
        {/* Top Control Header */}
        <header className="p-6 border-b border-outline-variant/40 bg-surface-container-lowest/10 flex justify-between items-center z-10">
          <div>
            <div className="text-[10px] text-on-surface-variant uppercase tracking-widest font-mono">OBSIDIAN SENTINEL CORE</div>
            <h1 className="font-sans font-bold text-xl sm:text-2xl text-on-surface mt-0.5">{getBreadcrumbLabel()}</h1>
          </div>

          <div className="flex items-center gap-4">
            
            {/* Live Indicator Beacon */}
            <div className="hidden sm:flex items-center gap-2 bg-[#005236]/30 border border-[#005236]/60 rounded-full py-1.5 px-3.5 text-xs text-[#4edea3] font-semibold">
              <span className="w-2 h-2 rounded-full bg-[#4edea3] animate-pulse"></span>
              VIGILANCE ENGINE ACTIVE
            </div>

            {/* Theme Toggle Button */}
            <button 
              onClick={toggleTheme}
              className="p-2.5 rounded-lg border border-outline-variant/60 bg-bg-card hover:bg-surface-container-high/40 text-on-surface-variant hover:text-on-surface transition-all cursor-pointer"
              title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
            >
              {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
            </button>

            {/* Notification Station Bell */}
            <div className="relative">
              <button 
                onClick={() => setShowNotifications(!showNotifications)}
                className="p-2.5 rounded-lg border border-outline-variant/60 bg-bg-card hover:bg-surface-container-high/40 text-on-surface-variant hover:text-on-surface transition-all cursor-pointer relative"
              >
                <Bell size={18} />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-error rounded-full animate-pulse"></span>
                )}
              </button>

              {/* Notification dropdown dropdown */}
              <AnimatePresence>
                {showNotifications && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    className="absolute right-0 mt-3 w-80 bg-bg-card border border-outline-variant rounded-xl shadow-2xl overflow-hidden z-50 p-4"
                  >
                    <div className="flex justify-between items-center border-b border-outline-variant/60 pb-3 mb-3">
                      <h4 className="text-xs font-bold text-on-surface uppercase tracking-wider">Alert Center</h4>
                      {unreadCount > 0 && (
                        <button 
                          onClick={handleClearNotifications}
                          className="text-[10px] text-primary hover:underline font-bold"
                        >
                          Clear All
                        </button>
                      )}
                    </div>
                    
                    <div className="space-y-3 max-h-60 overflow-y-auto">
                      {notifications.length > 0 ? (
                        notifications.map(n => (
                          <div key={n.id} className="text-xs text-on-surface-variant p-2 hover:bg-surface-container-high/20 rounded border border-outline-variant/30">
                            {n.text}
                          </div>
                        ))
                      ) : (
                        <p className="text-xs text-on-surface-variant text-center py-4">No active threat alerts in queue.</p>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        {/* View Component Screen Stage Container */}
        <div className="p-6 flex-1 overflow-y-auto max-w-7xl w-full mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.22, ease: 'easeOut' }}
              className="w-full h-full"
            >
              {renderActiveView()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>

      {/* Backdrop overlay for mobile menu */}
      {isMobileMenuOpen && (
        <div 
          onClick={() => setIsMobileMenuOpen(false)} 
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 md:hidden"
        ></div>
      )}
    </div>
  );
}
