import React, { useState } from 'react';
import { 
  BarChart3, 
  Search, 
  Database, 
  BrainCircuit, 
  Network, 
  FileText, 
  HelpCircle, 
  BookOpen, 
  Bell, 
  Settings, 
  Plus, 
  Activity,
  User,
  LayoutDashboard
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '@/src/lib/utils';
import Dashboard from './components/Dashboard';
import LogExplorer from './components/LogExplorer';
import ThreatHunting from './components/ThreatHunting';
import NetworkMap from './components/NetworkMap';

type View = 'dashboard' | 'threat-hunting' | 'log-explorer' | 'ai-insights' | 'network-map' | 'reports';

export default function App() {
  const [activeView, setActiveView] = useState<View>('dashboard');

  return (
    <div className="flex h-screen bg-background text-on-surface overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0B0F14] border-r border-outline-variant/30 flex flex-col pt-6 pb-6 shrink-0">
        <div className="px-6 mb-8 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-surface-container-highest border border-outline-variant flex items-center justify-center">
            <Activity className="text-primary w-6 h-6" />
          </div>
          <div>
            <div className="text-primary font-black tracking-tight text-sm uppercase">Hybrid SIEM</div>
            <div className="text-emerald-500 text-[10px] flex items-center gap-1 mt-0.5 font-bold uppercase tracking-wider">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981]" />
              Vigilance Active
            </div>
          </div>
        </div>

        <nav className="flex-1 flex flex-col gap-1">
          <NavItem 
            icon={<LayoutDashboard size={20} />} 
            label="Dashboard" 
            active={activeView === 'dashboard'} 
            onClick={() => setActiveView('dashboard')} 
          />
          <NavItem 
            icon={<Search size={20} />} 
            label="Threat Hunting" 
            active={activeView === 'threat-hunting'} 
            onClick={() => setActiveView('threat-hunting')} 
          />
          <NavItem 
            icon={<Database size={20} />} 
            label="Log Explorer" 
            active={activeView === 'log-explorer'} 
            onClick={() => setActiveView('log-explorer')} 
          />
          <NavItem 
            icon={<BrainCircuit size={20} />} 
            label="AI Insights" 
            active={activeView === 'ai-insights'} 
            onClick={() => setActiveView('ai-insights')} 
          />
          <NavItem 
            icon={<Network size={20} />} 
            label="Network Map" 
            active={activeView === 'network-map'} 
            onClick={() => setActiveView('network-map')} 
          />
          <NavItem 
            icon={<FileText size={20} />} 
            label="Reports" 
            active={activeView === 'reports'} 
            onClick={() => setActiveView('reports')} 
          />
        </nav>

        <div className="mt-auto flex flex-col gap-1 border-t border-outline-variant/20 pt-4">
          <NavItem icon={<HelpCircle size={18} />} label="Support" onClick={() => {}} />
          <NavItem icon={<BookOpen size={18} />} label="Documentation" onClick={() => {}} />
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Navbar */}
        <header className="h-16 bg-[#0B0F14]/80 backdrop-blur-lg border-b border-outline-variant/30 flex justify-between items-center px-6 sticky top-0 z-50">
          <div className="flex items-center gap-4 flex-1">
            <h2 className="text-lg font-bold tracking-tight text-slate-100 mr-8">Aegis AI SIEM</h2>
            <div className="relative group max-w-md w-full">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant w-4.5 h-4.5 group-focus-within:text-primary transition-colors" />
              <input 
                type="text" 
                placeholder="Search entity, IP, or query..." 
                className="bg-surface-container-low border border-outline-variant rounded-lg pl-10 pr-4 py-1.5 text-sm w-full focus:outline-none focus:border-primary/50 transition-all"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <NavAction icon={<BarChart3 size={20} />} />
            <NavAction icon={<Bell size={20} />} hasBadge />
            <NavAction icon={<Settings size={20} />} />
            <div className="w-px h-6 bg-outline-variant/30 mx-2" />
            <button className="bg-primary hover:bg-primary-container text-on-primary px-4 py-1.5 rounded-lg font-semibold text-sm transition-all shadow-[0_0_15px_rgba(173,198,255,0.2)] flex items-center gap-2">
              <Plus size={16} strokeWidth={3} />
              Deploy Agent
            </button>
            <div className="ml-4 w-9 h-9 rounded-lg bg-surface-container-high border border-outline-variant overflow-hidden cursor-pointer hover:border-primary transition-all">
              <img 
                src="https://lh3.googleusercontent.com/aida-public/AB6AXuBsc_6LsXrQjFIsguCRGu8iIHvb20XzLNMWcWf5JdJV82-aIiMW2DOKDod9Cm51adsUbAmtVeJovmOc65PWsQYbRB0Lu9q02EasZ6QNqtn4M0AgBzEHERcJN4RwaaoYmXVUruo4tdnhKa-2g1DyCJb47GbYEnBWn1ZZmvoGelcY8Z4l7Mn_Zve2iyOaV_-hxtIrQWyI-708Me_ZErEZCH7stSAZKDNIMcVagDCM5Bza_vWaLn0O2iffbhktVOqZZLx8mmaycPG3AplD" 
                alt="Profile" 
                className="w-full h-full object-cover"
              />
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-hidden relative">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeView}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="h-full"
            >
              {activeView === 'dashboard' && <Dashboard />}
              {activeView === 'log-explorer' && <LogExplorer />}
              {activeView === 'threat-hunting' && <ThreatHunting />}
              {activeView === 'network-map' && <NetworkMap />}
              {(activeView !== 'dashboard' && activeView !== 'log-explorer' && activeView !== 'threat-hunting' && activeView !== 'network-map') && (
                <div className="p-8 text-center text-on-surface-variant flex flex-col items-center justify-center h-full gap-4">
                  <Activity size={48} className="text-outline-variant" />
                  <p className="text-xl font-medium">This module is under construction</p>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }: { icon: React.ReactNode, label: string, active?: boolean, onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 px-6 py-3 text-xs font-semibold uppercase tracking-wider transition-all relative group",
        active ? "bg-primary/10 text-primary border-r-2 border-primary" : "text-on-surface-variant hover:bg-surface-container/50 hover:text-on-surface"
      )}
    >
      <span className={cn("transition-colors", active ? "text-primary" : "text-on-surface-variant group-hover:text-on-surface")}>
        {icon}
      </span>
      {label}
    </button>
  );
}

function NavAction({ icon, hasBadge }: { icon: React.ReactNode, hasBadge?: boolean }) {
  return (
    <button className="p-2 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all rounded-lg relative">
      {icon}
      {hasBadge && <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-primary rounded-full shadow-[0_0_8px_#adc6ff]" />}
    </button>
  );
}
