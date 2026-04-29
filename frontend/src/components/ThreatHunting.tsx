import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, History, Gavel, BrainCircuit, ShieldX,
  TrendingUp, ChevronRight, Globe, Database, Users, Activity, Terminal
} from 'lucide-react';
import { cn } from '../lib/utils';
import { motion } from 'motion/react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { useSIEMStream } from '../hooks/useSIEMStream';
import { getHuntingResults, type HuntingResult } from '../lib/api';

// ─── Component ────────────────────────────────────────────────────────────────

export default function ThreatHunting() {
  const { events, telemetry } = useSIEMStream();

  // Pick highest-risk event from live events as the "active incident"
  const target: HuntingResult | null = useMemo(() => {
    if (!events || events.length === 0) {
      return getHuntingResults(1)[0] ?? null; // Fallback to mock if no events
    }
    
    // Find highest-risk event and convert to HuntingResult
    const topEvent = [...events].sort((a, b) => b.risk_score - a.risk_score)[0];
    if (!topEvent) return null;
    
    return {
      ip: topEvent.ip,
      rule_score: topEvent.rule_score,
      anomaly_score: topEvent.anomaly_score,
      risk_score: topEvent.risk_score,
      risk_level: topEvent.risk_level,
      action: topEvent.action,
      strike_count: topEvent.strike_count,
      scoring_method: topEvent.scoring_method,
      reasons: topEvent.reasons,
      temporal_insight: topEvent.temporal_insight,
      first_seen: topEvent.timestamp,
      last_seen: topEvent.timestamp,
    };
  }, [events]);

  // Build trend data from live telemetry
  const trendData = useMemo(() =>
    telemetry.map(p => ({
      name: p.time,
      risk: Math.round((p.risk / 9800) * 100),
      req:  p.volume,
    })),
  [telemetry]);

  if (!target) {
    return (
      <div className="flex items-center justify-center h-full text-on-surface-variant">
        Loading threat data...
      </div>
    );
  }

  const riskPct     = Math.round(target.risk_score);
  const dashOffset  = 251.2 - (251.2 * riskPct) / 100;
  const isBlocked   = target.action === 'block';
  const isRateLim   = target.action === 'rate_limit';
  const confidencePct = Math.round(target.anomaly_score * 100);

  const actionLabel = isBlocked ? 'Blocked' : isRateLim ? 'Rate Limited' : 'Monitoring';

  // Factor cards driven by target
  const factors = [
    { title: 'failed_count',      value: String(Math.round(target.risk_score * 5)),  icon: <Terminal size={18} />, status: riskPct >= 85 ? 'CRITICAL THRESHOLD' : 'ELEVATED', percentage: riskPct,         color: 'error'   as const },
    { title: 'request_rate',      value: `${(target.anomaly_score * 150).toFixed(0)}/s`, icon: <Activity size={18} />, status: 'ELEVATED', percentage: Math.round(target.anomaly_score * 100),  color: 'tertiary' as const },
    { title: 'username_variance', value: target.anomaly_score.toFixed(2),            icon: <Users size={18} />,    status: 'HIGH SPREAD', percentage: Math.round(target.anomaly_score * 100),  color: 'error'   as const },
    { title: 'anomaly_score',     value: target.anomaly_score.toFixed(2),            icon: <BrainCircuit size={18} />, status: 'AI CONFIDENCE', percentage: confidencePct, color: 'primary' as const },
  ];

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
            <span className="text-on-surface">INC-{Math.abs(target.ip.split('.').reduce((a,b) => a + parseInt(b), 0))}</span>
          </div>
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold text-on-surface flex items-center gap-3">
              <Globe className="text-outline-variant" />
              {target.ip}
            </h1>
            <div className={cn(
              'border px-3 py-1 rounded-full flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest',
              isBlocked  ? 'bg-error/10 border-error/40 text-error' :
              isRateLim  ? 'bg-tertiary/10 border-tertiary/40 text-tertiary' :
              'bg-primary/10 border-primary/40 text-primary',
            )}>
              <ShieldAlert size={14} />
              {target.risk_level.charAt(0).toUpperCase() + target.risk_level.slice(1)} Risk
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
          <h3 className="text-sm font-bold text-on-surface-variant uppercase tracking-widest self-start w-full border-b border-outline-variant/20 pb-4 mb-6">
            Aggregate Risk Score
          </h3>

          <div className="relative w-48 h-48 flex items-center justify-center">
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
                animate={{ strokeDashoffset: dashOffset }}
                transition={{ duration: 1.5, ease: 'easeOut' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-5xl font-black text-error">{riskPct}</span>
              <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest mt-1">out of 100</span>
            </div>
          </div>

          <p className="mt-8 text-xs text-on-surface-variant text-center max-w-[220px] leading-relaxed">
            Score derived from AI behavioral analysis ({target.scoring_method} method) and rule-based triggers.
          </p>
        </div>

        {/* AI Decision Engine */}
        <div className="col-span-12 md:col-span-8 bg-surface-container rounded-xl border border-outline-variant/30 p-6 flex flex-col">
          <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4 mb-6">
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
              <BrainCircuit className="text-primary" size={18} />
              AI Decision Engine
            </h3>
            <span className="bg-surface-container-highest px-2 py-1 rounded text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
              Confidence: {confidencePct}%
            </span>
          </div>

          <div className="flex items-center justify-between mb-8 bg-surface-container-low/50 p-1.5 rounded-xl border border-outline-variant/10">
            <DecisionStep label="Normal"     active={target.action === 'monitor' && target.risk_level === 'normal'} />
            <DecisionStep label="Monitoring" active={target.action === 'monitor' && target.risk_level !== 'normal'} />
            <DecisionStep label="Rate Limited" active={target.action === 'rate_limit'} />
            <DecisionStep label="Blocked"    active={target.action === 'block'} variant="error" />
          </div>

          <div className="bg-surface-container-low border border-outline-variant/20 rounded-xl p-6 relative overflow-hidden">
            <div className={cn('absolute left-0 top-0 bottom-0 w-1', isBlocked ? 'bg-error' : isRateLim ? 'bg-tertiary' : 'bg-primary')} />
            <h4 className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-3 flex items-center gap-2">
              <Terminal size={14} className="text-error" />
              Automated Rationale
            </h4>
            <p className="text-sm text-on-surface-variant leading-relaxed">
              {target.reasons.map((r, i) => (
                <span key={i}>
                  {i > 0 && ' · '}
                  <span className={i === 0 ? 'text-on-surface font-medium' : ''}>{r}</span>
                </span>
              ))}
              {target.temporal_insight && (
                <> · <span className="text-primary font-bold">{target.temporal_insight}</span></>
              )}
            </p>
          </div>
        </div>

        {/* Risk Factor Breakdown */}
        <div className="col-span-12">
          <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest border-b border-outline-variant/20 pb-4 mb-6">
            Risk Factor Breakdown
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {factors.map(f => (
              <FactorCard key={f.title} {...f} />
            ))}
          </div>
        </div>

        {/* Activity & Trend */}
        <div className="col-span-12 bg-surface-container rounded-xl border border-outline-variant/30 p-6">
          <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4 mb-6">
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
              <TrendingUp className="text-outline-variant" size={18} />
              Activity &amp; Risk Trend (Live)
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
                    <stop offset="5%"  stopColor="#ffb4ab" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ffb4ab" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#424754" vertical={false} opacity={0.2} />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#8c909f', fontFamily: 'monospace' }} />
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

// ─── Sub-components ───────────────────────────────────────────────────────────

function DecisionStep({ label, active, variant }: { label: string; active?: boolean; variant?: 'error' }) {
  return (
    <div className={cn(
      'flex-1 text-center py-2 rounded-lg font-mono text-[10px] font-bold uppercase tracking-widest transition-all',
      active
        ? (variant === 'error' ? 'bg-error text-on-error shadow-[0_0_15px_#ffb4ab]' : 'bg-primary text-on-primary')
        : 'text-on-surface-variant/40',
    )}>
      {active && <ShieldX size={12} className="inline mr-2 mb-0.5" />}
      {label}
    </div>
  );
}

function FactorCard({ title, value, icon, status, percentage, color }: {
  title: string; value: string; icon: React.ReactNode;
  status: string; percentage: number; color: 'error' | 'primary' | 'tertiary';
}) {
  const colorClass   = color === 'error' ? 'text-error'   : color === 'primary' ? 'text-primary'   : 'text-tertiary';
  const bgColorClass = color === 'error' ? 'bg-error'     : color === 'primary' ? 'bg-primary'     : 'bg-tertiary';

  return (
    <div className="bg-surface-container-low p-5 rounded-xl border border-outline-variant/10 flex flex-col justify-between group hover:border-outline-variant transition-colors ring-1 ring-inset ring-transparent hover:ring-outline-variant/30">
      <div className="flex justify-between items-start mb-6">
        <div className="space-y-1">
          <div className="text-on-surface-variant/50">{icon}</div>
          <h4 className="font-mono text-xs text-on-surface font-semibold">{title}</h4>
        </div>
        <span className={cn('text-2xl font-black leading-none', colorClass)}>{value}</span>
      </div>
      <div>
        <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden mb-2">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${percentage}%` }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            className={cn('h-full', bgColorClass)}
          />
        </div>
        <p className={cn('text-[9px] font-black uppercase tracking-widest text-right', colorClass)}>{status}</p>
      </div>
    </div>
  );
}

function LegendItem({ color, label, isCircle }: { color: string; label: string; isCircle?: boolean }) {
  return (
    <div className={cn('flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest', label.includes('Risk') ? 'text-error' : 'text-on-surface-variant')}>
      <div className={cn('w-3 h-3 border border-outline-variant/30', color, isCircle ? 'rounded-full' : 'rounded-sm')} />
      {label}
    </div>
  );
}
