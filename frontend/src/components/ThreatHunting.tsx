import React from 'react';
import { 
  ShieldAlert, 
  History, 
  Gavel, 
  Search, 
  BrainCircuit, 
  ShieldX, 
  Zap, 
  CheckCircle2, 
  AlertCircle,
  TrendingUp,
  MoreHorizontal,
  ChevronRight,
  Globe,
  Database,
  Users,
  Activity
} from 'lucide-react';
import { cn } from '@/src/lib/utils';
import { motion } from 'motion/react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  BarChart, 
  Bar,
  Cell
} from 'recharts';

const trendData = [
  { name: 'T-24h', risk: 30, req: 100 },
  { name: 'T-20h', risk: 25, req: 120 },
  { name: 'T-16h', risk: 28, req: 110 },
  { name: 'T-12h', risk: 45, req: 200 },
  { name: 'T-8h', risk: 60, req: 380 },
  { name: 'T-4h', risk: 85, req: 850 },
  { name: 'Now', risk: 88, req: 980 },
];

export default function ThreatHunting() {
  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      {/* Header Section */}
      <div className="flex items-end justify-between border-b border-outline-variant/30 pb-6">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-on-surface-variant font-medium text-xs mb-2">
            <span>Threat Hunting</span>
            <ChevronRight size={14} />
            <span>Active Incidents</span>
            <ChevronRight size={14} />
            <span className="text-on-surface">INC-8492</span>
          </div>
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold text-on-surface flex items-center gap-3">
              <Globe className="text-outline-variant" />
              192.168.1.105
            </h1>
            <div className="bg-error/10 border border-error/40 text-error px-3 py-1 rounded-full flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest">
              <ShieldAlert size={14} />
              Critical Risk
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="bg-surface-container border border-outline-variant/30 hover:bg-surface-container-high text-on-surface px-4 py-2 rounded-lg font-semibold text-xs flex items-center gap-2 transition-all">
            <History size={16} />
            View History
          </button>
          <button className="bg-primary hover:bg-primary-container text-on-primary px-4 py-2 rounded-lg font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(173,198,255,0.2)]">
            <Gavel size={16} />
            Enforce Policy
          </button>
        </div>
      </div>

      {/* Bento Grid layout */}
      <div className="grid grid-cols-12 gap-6">
        {/* Risk Score Gauge */}
        <div className="col-span-12 md:col-span-4 bg-surface-container rounded-xl border border-outline-variant/30 p-6 flex flex-col items-center justify-center relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-error to-transparent opacity-50 transition-opacity group-hover:opacity-100" />
          <h3 className="text-sm font-bold text-on-surface-variant uppercase tracking-widest self-start w-full border-b border-outline-variant/20 pb-4 mb-6">Aggregate Risk Score</h3>
          
          <div className="relative w-48 h-48 flex items-center justify-center">
            {/* SVG Donut Chart */}
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="40" className="text-surface-container-highest" fill="transparent" stroke="currentColor" strokeWidth="8" />
              <motion.circle 
                cx="50" cy="50" r="40" 
                className="text-error" 
                fill="transparent" 
                stroke="currentColor" 
                strokeWidth="8" 
                strokeLinecap="round" 
                strokeDasharray="251.2" 
                initial={{ strokeDashoffset: 251.2 }}
                animate={{ strokeDashoffset: 251.2 - (251.2 * 88) / 100 }}
                transition={{ duration: 1.5, ease: 'easeOut' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-5xl font-black text-error">88</span>
              <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest mt-1">out of 100</span>
            </div>
          </div>
          <p className="mt-8 text-xs text-on-surface-variant text-center max-w-[220px] leading-relaxed">
            Score derived from AI behavioral analysis and rule-based triggers over 24h.
          </p>
        </div>

        {/* AI Decision Engine */}
        <div className="col-span-12 md:col-span-8 bg-surface-container rounded-xl border border-outline-variant/30 p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4 mb-6">
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
              <BrainCircuit className="text-primary" size={18} />
              AI Decision Engine
            </h3>
            <span className="bg-surface-container-highest px-2 py-1 rounded text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">Confidence: 94%</span>
          </div>

          <div className="flex items-center justify-between mb-8 bg-surface-container-low/50 p-1.5 rounded-xl border border-outline-variant/10">
            <DecisionStep label="Normal" />
            <DecisionStep label="Monitoring" />
            <DecisionStep label="Rate Limited" />
            <DecisionStep label="Blocked" active variant="error" />
          </div>

          <div className="bg-surface-container-low border border-outline-variant/20 rounded-xl p-6 relative overflow-hidden">
            <div className="absolute left-0 top-0 bottom-0 w-1 bg-error" />
            <h4 className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-3 flex items-center gap-2">
              <Terminal size={14} className="text-error" />
              Automated Rationale
            </h4>
            <p className="text-sm text-on-surface-variant leading-relaxed">
              Entity exhibits a highly anomalous access pattern consistent with a distributed brute-force attack. 
              <span className="text-error font-bold mx-1">failed_count</span> threshold exceeded by 400%, coupled with a high <span className="text-primary font-bold mx-1">username_variance</span> across targeted endpoints. 
              The AI anomaly model classifies this behavior cluster as malicious with high certainty. Immediate blocking is enforced at the edge firewall.
            </p>
          </div>
        </div>

        {/* Risk Factor Breakdown */}
        <div className="col-span-12">
          <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest border-b border-outline-variant/20 pb-4 mb-6">Risk Factor Breakdown</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <FactorCard title="failed_count" value="452" icon={<Terminal size={18} />} status="CRITICAL THRESHOLD" percentage={95} color="error" />
            <FactorCard title="request_rate" value="120/s" icon={<Activity size={18} />} status="ELEVATED" percentage={65} color="tertiary" />
            <FactorCard title="username_variance" value="0.85" icon={<Users size={18} />} status="HIGH SPREAD" percentage={85} color="error" />
            <FactorCard title="anomaly_score" value="0.92" icon={<BrainCircuit size={18} />} status="AI CONFIDENCE" percentage={92} color="primary" />
          </div>
        </div>

        {/* Activity & Trend */}
        <div className="col-span-12 bg-surface-container rounded-xl border border-outline-variant/30 p-6">
          <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4 mb-6">
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
              <TrendingUp className="text-outline-variant" size={18} />
              Activity & Risk Trend (24h)
            </h3>
            <div className="flex gap-4">
              <LegendItem color="bg-surface-bright" label="Req Volume" />
              <LegendItem color="bg-error" label="Risk Score" isCircle />
            </div>
          </div>
          
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="100%">
                    <stop offset="5%" stopColor="#ffb4ab" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ffb4ab" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#424754" vertical={false} opacity={0.2} />
                <XAxis 
                  dataKey="name" 
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 10, fill: '#8c909f', fontFamily: 'monospace' }} 
                />
                <YAxis hide />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }}
                  itemStyle={{ fontSize: '11px', fontWeight: 'bold' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="risk" 
                  stroke="#ffb4ab" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#colorRisk)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

function DecisionStep({ label, active, variant }: { label: string, active?: boolean, variant?: 'error' }) {
  return (
    <div className={cn(
      "flex-1 text-center py-2 rounded-lg font-mono text-[10px] font-bold uppercase tracking-widest transition-all",
      active ? (variant === 'error' ? "bg-error text-on-error shadow-[0_0_15px_#ffb4ab]" : "bg-primary text-on-primary") : "text-on-surface-variant/40"
    )}>
      {active && <ShieldX size={12} className="inline mr-2 mb-0.5" />}
      {label}
    </div>
  );
}

function FactorCard({ title, value, icon, status, percentage, color }: { 
  title: string, value: string, icon: React.ReactNode, status: string, percentage: number, color: 'error' | 'primary' | 'tertiary' 
}) {
  const colorClass = color === 'error' ? 'text-error' : color === 'primary' ? 'text-primary' : 'text-tertiary';
  const bgColorClass = color === 'error' ? 'bg-error' : color === 'primary' ? 'bg-primary' : 'bg-tertiary';

  return (
    <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant/10 flex flex-col justify-between group hover:border-outline-variant transition-colors ring-1 ring-inset ring-transparent hover:ring-outline-variant/30">
      <div className="flex justify-between items-start mb-6">
        <div className="space-y-1">
          <div className="text-on-surface-variant/50">{icon}</div>
          <h4 className="font-mono text-xs text-on-surface font-semibold">{title}</h4>
        </div>
        <span className={cn("text-2xl font-black leading-none", colorClass)}>{value}</span>
      </div>
      <div>
        <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden mb-2">
          <motion.div 
            initial={{ width: 0 }}
            animate={{ width: `${percentage}%` }}
            className={cn("h-full", bgColorClass)} 
          />
        </div>
        <p className={cn("text-[9px] font-black uppercase tracking-widest text-right", colorClass)}>{status}</p>
      </div>
    </div>
  );
}

function LegendItem({ color, label, isCircle }: { color: string, label: string, isCircle?: boolean }) {
  return (
    <div className={cn("flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest", label.includes('Risk') ? 'text-error' : 'text-on-surface-variant')}>
      <div className={cn("w-3 h-3 border  border-outline-variant/30", color, isCircle ? "rounded-full" : "rounded-sm")} />
      {label}
    </div>
  );
}
