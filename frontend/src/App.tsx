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
import AIInsights from './components/AIInsights';
import Reports from './components/Reports';
import Login from './components/Login';
import { useSIEMStream } from './hooks/useSIEMStream';
import { ShieldAlert, X, ShieldCheck, Globe, MapPin, LogOut } from 'lucide-react';

type View = 'dashboard' | 'threat-hunting' | 'log-explorer' | 'ai-insights' | 'network-map' | 'reports';

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('siem_token'));
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [dismissedToasts, setDismissedToasts] = useState<Set<string>>(new Set());

  const { events, searchQuery, setSearchQuery, selectedIp, setSelectedIp, connectionStatus } = useSIEMStream();
  
  // Badge: Count CRIT events
  const critEvents = events.filter(e => e.risk_level === 'high' || e.risk_level === 'medium');
  
  // Toast: Show latest blocked event (risk >= 85) if not dismissed
  const latestBlock = events.find(e => e.risk_score >= 85);
  const showToast = latestBlock && !dismissedToasts.has(latestBlock.id);

  const handleLogin = (newToken: string) => {
    localStorage.setItem('siem_token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('siem_token');
    setToken(null);
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen bg-background text-on-surface overflow-hidden relative">
      {/* Toast Notification */}
      <AnimatePresence>
        {showToast && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.9 }}
            className="absolute bottom-6 right-6 z-[60] bg-surface-container-high border border-error/40 shadow-[0_8px_30px_rgb(0,0,0,0.5)] rounded-xl p-4 min-w-[320px] flex gap-4"
          >
            <div className="w-10 h-10 rounded-full bg-error/20 flex items-center justify-center shrink-0">
              <ShieldAlert className="text-error" size={20} />
            </div>
            <div className="flex-1">
              <div className="flex justify-between items-start">
                <h4 className="text-sm font-bold text-on-surface">CRITICAL THREAT BLOCKED</h4>
                <button onClick={() => setDismissedToasts(prev => new Set(prev).add(latestBlock!.id))} className="text-on-surface-variant hover:text-on-surface">
                  <X size={16} />
                </button>
              </div>
              <p className="text-xs text-on-surface-variant mt-1">IP <span className="font-mono text-error font-bold">{latestBlock?.ip}</span> isolated.</p>
              <div className="mt-2 text-[10px] font-mono text-on-surface-variant bg-surface-container-low p-2 rounded truncate border border-outline-variant/30">
                {latestBlock?.reasons[0]}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* IP Drill-down Modal */}
      <AnimatePresence>
        {selectedIp && (
          <>
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="absolute inset-0 bg-background/80 backdrop-blur-sm z-[70]"
              onClick={() => setSelectedIp(null)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[80] bg-surface-container border border-outline-variant/30 rounded-2xl p-6 w-full max-w-lg shadow-2xl flex flex-col gap-6"
            >
              <div className="flex justify-between items-start border-b border-outline-variant/30 pb-4">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-full bg-surface-container-high border border-outline-variant/50 flex items-center justify-center">
                    <Globe className="text-primary" size={24} />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold font-mono text-on-surface">{selectedIp}</h2>
                    <p className="text-xs text-on-surface-variant uppercase tracking-widest font-bold flex items-center gap-1 mt-1">
                      <MapPin size={12} /> Unknown Location
                    </p>
                  </div>
                </div>
                <button onClick={() => setSelectedIp(null)} className="text-on-surface-variant hover:text-on-surface p-1 rounded-lg hover:bg-surface-container-highest transition-colors">
                  <X size={20} />
                </button>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant/20 flex flex-col gap-1">
                  <span className="text-[10px] uppercase font-bold text-on-surface-variant tracking-widest">Total Events (24h)</span>
                  <span className="text-xl font-black text-on-surface">{events.filter(e => e.ip === selectedIp).length}</span>
                </div>
                <div className="bg-surface-container-low p-4 rounded-xl border border-outline-variant/20 flex flex-col gap-1">
                  <span className="text-[10px] uppercase font-bold text-on-surface-variant tracking-widest">Last Activity</span>
                  <span className="text-sm font-bold text-on-surface mt-auto">Just now</span>
                </div>
              </div>

              <div className="flex gap-3 mt-2">
                <button 
                  onClick={() => {
                    setSearchQuery(selectedIp);
                    setActiveView('log-explorer');
                    setSelectedIp(null);
                  }}
                  className="flex-1 py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-surface-container-highest transition-colors text-on-surface"
                >
                  View Logs
                </button>
                <button className="flex-1 py-2 bg-error/10 border border-error/40 text-error rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-error/20 transition-colors">
                  Block IP
                </button>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <aside className="w-64 bg-[#0B0F14] border-r border-outline-variant/30 flex flex-col pt-6 pb-6 shrink-0">
        <div className="px-6 mb-8 flex items-center gap-3">
          <div className="w-10 h-10 bg-primary/10 rounded-xl flex items-center justify-center border border-primary/20 overflow-hidden">
            <img 
              src="/assets/logo.png" 
              alt="Logo" 
              className="w-full h-full object-contain"
              onError={(e) => {
                e.currentTarget.style.display = 'none';
                const fallback = e.currentTarget.nextElementSibling;
                if (fallback) (fallback as HTMLElement).style.display = 'block';
              }}
            />
            <ShieldCheck className="text-primary" size={24} style={{ display: 'none' }} />
          </div>
          <span className="font-black text-xl tracking-tighter text-white">AEGIS</span>
        </div>
        <div className="px-6 mb-8">
            <div className="text-emerald-500 text-[10px] flex items-center gap-1 mt-0.5 font-bold uppercase tracking-wider">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981]" />
              Vigilance Active
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
          <NavItem icon={<LogOut size={18} />} label="Logout" onClick={handleLogout} />
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Navbar */}
        <header className="h-16 bg-[#0B0F14]/80 backdrop-blur-lg border-b border-outline-variant/30 flex justify-between items-center px-6 sticky top-0 z-50">
          <div className="flex items-center gap-4 flex-1">
            <div className="w-8 h-8 rounded-lg bg-surface-container-high border border-outline-variant/50 flex items-center justify-center overflow-hidden">
              <img 
                src="/assets/logo.png" 
                alt="Logo" 
                className="w-full h-full object-contain"
                onError={(e) => {
                  e.currentTarget.style.display = 'none';
                  const fallback = e.currentTarget.nextElementSibling;
                  if (fallback) (fallback as HTMLElement).style.display = 'block';
                }}
              />
              <ShieldCheck className="text-primary" size={18} style={{ display: 'none' }} />
            </div>
            <h2 className="text-lg font-bold tracking-tight text-slate-100 mr-4">Aegis AI SIEM</h2>
            <div className={cn(
              "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border flex items-center gap-1.5 mr-4",
              connectionStatus === 'CONNECTED' ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" :
              connectionStatus === 'CONNECTING' ? "bg-tertiary/10 text-tertiary border-tertiary/20" :
              "bg-error/10 text-error border-error/20 animate-pulse"
            )}>
              <span className={cn("w-1.5 h-1.5 rounded-full", 
                connectionStatus === 'CONNECTED' ? "bg-emerald-500" :
                connectionStatus === 'CONNECTING' ? "bg-tertiary animate-ping" : "bg-error"
              )} />
              {connectionStatus}
            </div>
            <div className="relative group max-w-md w-full">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant w-4.5 h-4.5 group-focus-within:text-primary transition-colors" />
              <input 
                type="text" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search entity, IP, or query..." 
                className="bg-surface-container-low border border-outline-variant rounded-lg pl-10 pr-4 py-1.5 text-sm w-full focus:outline-none focus:border-primary/50 transition-all text-on-surface"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <NavAction icon={<BarChart3 size={20} />} />
            <NavAction icon={<Bell size={20} />} badgeCount={critEvents.length} />
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
              {activeView === 'network-map' && <NetworkMap onNavigate={setActiveView} />}
              {activeView === 'ai-insights' && <AIInsights />}
              {activeView === 'reports' && <Reports />}
              {(activeView !== 'dashboard' && activeView !== 'log-explorer' && activeView !== 'threat-hunting' && activeView !== 'network-map' && activeView !== 'ai-insights' && activeView !== 'reports') && (
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

function NavAction({ icon, badgeCount }: { icon: React.ReactNode, badgeCount?: number }) {
  return (
    <button className="p-2 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all rounded-lg relative">
      {icon}
      {!!badgeCount && badgeCount > 0 && (
        <span className="absolute top-1 right-1 px-1 min-w-[14px] h-[14px] bg-error rounded-full text-[8px] font-bold text-on-error flex items-center justify-center shadow-[0_0_8px_#ffb4ab]">
          {badgeCount > 99 ? '99+' : badgeCount}
        </span>
      )}
    </button>
  );
}
