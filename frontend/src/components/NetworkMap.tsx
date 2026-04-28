import React from 'react';
import { 
  Network, 
  Database, 
  Globe, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Search, 
  Filter,
  Maximize2,
  ZoomIn,
  ZoomOut
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';

const volumeData = [
  { name: '13:00', vol: 2000 },
  { name: '13:10', vol: 2500 },
  { name: '13:20', vol: 1800 },
  { name: '13:30', vol: 3200 },
  { name: '13:40', vol: 2400 },
  { name: '13:50', vol: 3000 },
  { name: '14:00', vol: 8500, isAnomaly: true },
  { name: '14:10', vol: 9200, isAnomaly: true },
  { name: '14:20', vol: 4500 },
  { name: '14:30', vol: 3500 },
];

export default function NetworkMap() {
  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      {/* Header */}
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Attack Visualization</h1>
          <p className="text-sm text-on-surface-variant mt-1">AI-mapped lateral movement and exfiltration attempts.</p>
        </div>
        <div className="flex gap-2">
          <button className="h-9 px-4 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface transition-all text-xs font-bold uppercase tracking-wider">
            <Globe size={16} />
            Global View
          </button>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-6 flex-1 min-h-[500px]">
        {/* Network Map Visualizer */}
        <div className="col-span-12 lg:col-span-8 bg-[#080B0E] border border-outline-variant/20 rounded-xl overflow-hidden relative group">
          <div className="absolute inset-0 opacity-10" style={{ 
            backgroundImage: 'linear-gradient(#424754 1px, transparent 1px), linear-gradient(90deg, #424754 1px, transparent 1px)',
            backgroundSize: '40px 40px'
          }} />
          
          {/* Controls */}
          <div className="absolute top-4 right-4 flex flex-col gap-2 z-20">
            <ControlButton icon={<Maximize2 size={18} />} />
            <ControlButton icon={<ZoomIn size={18} />} />
            <ControlButton icon={<ZoomOut size={18} />} />
            <ControlButton icon={<Filter size={18} />} />
          </div>

          {/* SVG Map Layer */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <Connection x1="20%" y1="30%" x2="40%" y2="50%" status="neutral" />
            <Connection x1="40%" y1="50%" x2="65%" y2="35%" status="danger" animate />
            <Connection x1="65%" y1="35%" x2="85%" y2="55%" status="danger" animate />
            <Connection x1="40%" y1="50%" x2="35%" y2="75%" status="neutral" />
          </svg>

          {/* Nodes */}
          <Node x="20%" y="30%" icon={<Globe size={20} />} label="Ext: 185.15.22.90" />
          <Node x="40%" y="50%" icon={<Activity size={24} />} label="Proxy-DMZ-01" status="danger" isPulse />
          <Node x="65%" y="35%" icon={<Database size={20} />} label="Core-DB-Auth" status="danger" />
          <Node x="85%" y="55%" icon={<ShieldCheck size={20} />} label="FileShare-HR" status="success" />
          <Node x="35%" y="75%" icon={<Users size={20} />} label="User-Subnet-A" />

          {/* Legend */}
          <div className="absolute bottom-6 left-6 bg-surface-container/80 backdrop-blur-md p-4 rounded-xl border border-outline-variant/30 space-y-3 shadow-xl">
             <div className="flex items-center gap-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
               <div className="w-2.5 h-2.5 rounded-full bg-error shadow-[0_0_8px_#ffb4ab]" />
               Compromised Node
             </div>
             <div className="flex items-center gap-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
               <div className="w-2.5 h-2.5 rounded-full border border-outline-variant" />
               Investigating
             </div>
             <div className="flex items-center gap-3 text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
               <div className="w-4 h-0.5 bg-error" />
               Malicious Path
             </div>
          </div>
        </div>

        {/* Column 2 */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          {/* Volume Analysis */}
          <div className="bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col flex-1 max-h-[300px]">
            <div className="p-4 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container-low/50">
               <h3 className="text-xs font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
                 <Activity size={16} className="text-primary" />
                 Volume Analysis
               </h3>
               <span className="text-[10px] text-error font-bold flex items-center gap-1">
                 <ShieldAlert size={12} />
                 Spike Detected
               </span>
            </div>
            <div className="flex-1 p-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={volumeData}>
                  <Bar dataKey="vol">
                    {volumeData.map((entry, index) => (
                      <Cell key={index} fill={entry.isAnomaly ? '#ffb4ab' : '#adc6ff33'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* AI Insights Card */}
          <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex-1 flex flex-col gap-4">
            <div className="flex items-center gap-3 border-b border-outline-variant/20 pb-4">
               <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                 <BrainCircuit className="text-primary" size={20} />
               </div>
               <div>
                 <h4 className="text-sm font-bold text-on-surface">AI Pattern Confirmed</h4>
                 <p className="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest">92% Confidence Match</p>
               </div>
            </div>
            <div className="space-y-3">
              <InsightMetric label="Technique" value="T1078 (Valid Accts)" />
              <InsightMetric label="Tactic" value="Privilege Escalation" />
              <InsightMetric label="Deviation" value="+4.2σ from baseline" variant="error" />
            </div>
            <button className="mt-auto w-full py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-[10px] font-bold uppercase tracking-widest hover:bg-surface-bright transition-all">
              Investigate Chain
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ControlButton({ icon }: { icon: React.ReactNode }) {
  return (
    <button className="w-10 h-10 bg-surface-container/90 backdrop-blur-md rounded-lg border border-outline-variant/30 flex items-center justify-center text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all shadow-lg">
      {icon}
    </button>
  );
}

function Node({ x, y, icon, label, status, isPulse }: { x: string, y: string, icon: React.ReactNode, label: string, status?: 'danger' | 'success', isPulse?: boolean }) {
  return (
    <div 
      className="absolute flex flex-col items-center group cursor-pointer transition-transform hover:scale-110" 
      style={{ left: x, top: y, transform: 'translate(-50%, -50%)' }}
    >
      <div className={cn(
        "w-12 h-12 rounded-full flex items-center justify-center bg-[#14191F] border-2 shadow-2xl relative z-10",
        status === 'danger' ? "border-error text-error shadow-[0_0_20px_rgba(255,180,171,0.2)]" : 
        status === 'success' ? "border-emerald-500 text-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.1)]" : 
        "border-outline-variant text-on-surface-variant"
      )}>
        {isPulse && <span className="absolute inset-0 rounded-full bg-error animate-ping opacity-20" />}
        {icon}
      </div>
      <div className="mt-3 px-2 py-1 bg-surface-container-lowest/80 backdrop-blur-md border border-outline-variant/30 rounded text-[10px] font-mono whitespace-nowrap shadow-lg">
        {label}
      </div>
    </div>
  );
}

function Connection({ x1, y1, x2, y2, status, animate }: { x1: string, y1: string, x2: string, y2: string, status: 'danger' | 'neutral', animate?: boolean }) {
  return (
    <line 
      x1={x1} y1={y1} x2={x2} y2={y2} 
      stroke={status === 'danger' ? "#ffb4ab" : "#424754"} 
      strokeWidth={status === 'danger' ? "2" : "1.5"}
      strokeDasharray={status === 'neutral' ? "4 4" : "0"}
      className={cn(animate && "animate-pulse")}
      opacity={status === 'neutral' ? 0.3 : 0.6}
    />
  );
}

function InsightMetric({ label, value, variant }: { label: string, value: string, variant?: 'error' }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-on-surface-variant font-mono">{label}</span>
      <span className={cn("font-bold text-right", variant === 'error' ? "text-error" : "text-on-surface")}>{value}</span>
    </div>
  );
}
