import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  BrainCircuit,
  ChevronRight,
  Globe,
  Gavel,
  History,
  ShieldAlert,
  ShieldX,
  Terminal,
  TrendingUp,
  Users,
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import { fetchHuntingResultsAsync, type HuntingResult } from '../lib/api';
import { useSIEMStream } from '../hooks/useSIEMStream';

export default function ThreatHunting() {
  const { events, telemetry, setSelectedIp, enforcePolicy } = useSIEMStream();
  const [fallbackTarget, setFallbackTarget] = useState<HuntingResult | null>(null);
  const [activeTab, setActiveTab] = useState<'active' | 'review_queue'>('active');

  const manualReviewQueue = useMemo(() => {
    // Collect all unique IPs that need manual review
    const reviewEvents = events.filter((e) => e.action === 'escalate_manual_review');
    const uniqueIps = new Map<string, typeof reviewEvents[0]>();
    for (const e of reviewEvents) {
      if (!uniqueIps.has(e.ip) || e.risk_score > uniqueIps.get(e.ip)!.risk_score) {
        uniqueIps.set(e.ip, e);
      }
    }
    return Array.from(uniqueIps.values()).sort((a, b) => b.risk_score - a.risk_score);
  }, [events]);

  useEffect(() => {
    if (events.length > 0) return;
    let cancelled = false;
    fetchHuntingResultsAsync()
      .then((results) => {
        if (!cancelled) {
          setFallbackTarget(results[0] ?? null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFallbackTarget(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [events.length]);

  const target: HuntingResult | null = useMemo(() => {
    if (events.length === 0) {
      return fallbackTarget;
    }

    const topEvent = [...events].sort((left, right) => right.risk_score - left.risk_score)[0];
    if (!topEvent) return null;

    return {
      ...topEvent,
      first_seen: topEvent.timestamp,
      last_seen: topEvent.timestamp,
    };
  }, [events, fallbackTarget]);

  const trendData = useMemo(
    () =>
      telemetry.map((point) => ({
        name: point.time,
        risk: point.risk,
        req: point.volume,
      })),
    [telemetry],
  );

  if (!target) {
    return (
      <div className="flex items-center justify-center h-full text-on-surface-variant">
        Loading threat data...
      </div>
    );
  }

  const riskPct = Math.round(target.risk_score);
  const dashOffset = 251.2 - (251.2 * riskPct) / 100;
  const isBlocked = target.action === 'block';
  const isRateLimited = target.action === 'rate_limit';
  const confidencePct = Math.round(target.anomaly_score * 100);

  const factors = [
    {
      title: 'failed_count',
      value: String(target.failed_count),
      icon: <Terminal size={18} />,
      status: target.failed_count >= 8 ? 'CRITICAL THRESHOLD' : 'OBSERVED',
      percentage: Math.min(100, target.failed_count * 10),
      color: 'error' as const,
    },
    {
      title: 'request_rate',
      value: `${target.request_rate.toFixed(3)}/s`,
      icon: <Activity size={18} />,
      status: target.request_rate >= 0.08 ? 'ELEVATED' : 'BASELINE',
      percentage: Math.min(100, Math.round(target.request_rate * 1000)),
      color: 'tertiary' as const,
    },
    {
      title: 'username_variance',
      value: String(target.username_variance),
      icon: <Users size={18} />,
      status: target.username_variance <= 2 ? 'LOW DIVERSITY' : 'NORMAL SPREAD',
      percentage: Math.min(100, target.username_variance * 12),
      color: 'error' as const,
    },
    {
      title: 'anomaly_score',
      value: target.anomaly_score.toFixed(2),
      icon: <BrainCircuit size={18} />,
      status: 'AI CONFIDENCE',
      percentage: confidencePct,
      color: 'primary' as const,
    },
  ];

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <div className="flex items-end justify-between border-b border-outline-variant/30 pb-6">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-on-surface-variant font-medium text-xs mb-2">
            <span>Threat Hunting</span>
            <ChevronRight size={14} />
            <span>Active Incidents</span>
            <ChevronRight size={14} />
            <span className="text-on-surface">INC-{Math.abs(target.ip.split('.').reduce((sum, item) => sum + parseInt(item, 10), 0))}</span>
          </div>
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold text-on-surface flex items-center gap-3">
              <Globe className="text-outline-variant" />
              {target.ip}
            </h1>
            <div
              className={cn(
                'border px-3 py-1 rounded-full flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest',
                isBlocked ? 'bg-error/10 border-error/40 text-error' :
                isRateLimited ? 'bg-tertiary/10 border-tertiary/40 text-tertiary' :
                'bg-primary/10 border-primary/40 text-primary',
              )}
            >
              <ShieldAlert size={14} />
              {target.risk_level.charAt(0).toUpperCase() + target.risk_level.slice(1)} Risk
            </div>
          </div>
        </div>
        
        <div className="flex bg-surface-container-high p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('active')}
            className={cn('px-4 py-1.5 rounded-md text-xs font-bold transition-all', activeTab === 'active' ? 'bg-surface-container text-on-surface shadow-sm' : 'text-on-surface-variant hover:text-on-surface')}
          >
            Active Incident
          </button>
          <button
            onClick={() => setActiveTab('review_queue')}
            className={cn('px-4 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2', activeTab === 'review_queue' ? 'bg-surface-container text-on-surface shadow-sm' : 'text-on-surface-variant hover:text-on-surface')}
          >
            Manual Review Queue
            {manualReviewQueue.length > 0 && (
              <span className="bg-primary/20 text-primary px-1.5 py-0.5 rounded text-[10px]">{manualReviewQueue.length}</span>
            )}
          </button>
        </div>
      </div>

      {activeTab === 'review_queue' ? (
        <div className="flex flex-col gap-4">
          <div className="bg-surface-container rounded-xl border border-outline-variant/30 p-6">
            <div className="flex items-center gap-3 mb-6 border-b border-outline-variant/20 pb-4">
              <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                <BrainCircuit className="text-primary" size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-on-surface uppercase tracking-widest">Manual Review Queue</h2>
                <p className="text-xs text-on-surface-variant mt-0.5">Events flagged by AI due to low confidence or borderline risk scores.</p>
              </div>
            </div>
            
            {manualReviewQueue.length === 0 ? (
              <div className="py-12 flex flex-col items-center justify-center text-on-surface-variant gap-3">
                <ShieldAlert size={40} className="text-outline-variant" />
                <p className="text-sm font-medium">Queue is clear. No events require manual review.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {manualReviewQueue.map((item) => (
                  <div key={item.id} className="bg-surface-container-high border border-outline-variant/30 p-4 rounded-xl flex flex-col lg:flex-row gap-4 justify-between lg:items-center hover:border-outline-variant transition-all">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-3">
                        <span className="font-mono font-bold text-on-surface text-lg">{item.ip}</span>
                        <span className="px-2 py-0.5 rounded bg-surface-container-highest text-on-surface-variant text-[10px] font-bold uppercase tracking-widest border border-outline-variant/50">
                          AI Confidence: {Math.round(item.anomaly_score * 100)}%
                        </span>
                      </div>
                      <p className="text-xs text-on-surface-variant line-clamp-2">
                        {item.reasons.join(' · ')}
                      </p>
                    </div>
                    
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => setSelectedIp(item.ip)}
                        className="bg-surface-container hover:bg-surface-container-highest text-on-surface px-3 py-1.5 rounded text-xs font-bold uppercase tracking-widest transition-colors border border-outline-variant/30"
                      >
                        Investigate
                      </button>
                      <button
                        onClick={() => void enforcePolicy(item.ip, 'monitor', 'Reviewed: Set to Monitor')}
                        className="bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-widest transition-colors"
                      >
                        Monitor
                      </button>
                      <button
                        onClick={() => void enforcePolicy(item.ip, 'block', 'Reviewed: Enforced Block')}
                        className="bg-error/10 hover:bg-error/20 text-error border border-error/30 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-widest transition-colors"
                      >
                        Block
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-6">
        <div className="col-span-12 md:col-span-4 bg-surface-container rounded-xl border border-outline-variant/30 p-6 flex flex-col items-center justify-center relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-error to-transparent opacity-50 transition-opacity group-hover:opacity-100" />
          <h3 className="text-sm font-bold text-on-surface-variant uppercase tracking-widest self-start w-full border-b border-outline-variant/20 pb-4 mb-6">
            Aggregate Risk Score
          </h3>

          <div className="relative w-48 h-48 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="40" className="text-surface-container-highest" fill="transparent" stroke="currentColor" strokeWidth="8" />
              <motion.circle
                cx="50"
                cy="50"
                r="40"
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
            <DecisionStep label="Normal" active={target.action === 'monitor' && target.risk_level === 'normal'} />
            <DecisionStep label="Monitoring" active={target.action === 'monitor' && target.risk_level !== 'normal'} />
            <DecisionStep label="Rate Limited" active={target.action === 'rate_limit'} />
            <DecisionStep label="Blocked" active={target.action === 'block'} variant="error" />
          </div>

          <div className="bg-surface-container-low border border-outline-variant/20 rounded-xl p-6 relative overflow-hidden">
            <div className={cn('absolute left-0 top-0 bottom-0 w-1', isBlocked ? 'bg-error' : isRateLimited ? 'bg-tertiary' : 'bg-primary')} />
            <h4 className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-3 flex items-center gap-2">
              <Terminal size={14} className="text-error" />
              Automated Rationale
            </h4>
            <p className="text-sm text-on-surface-variant leading-relaxed">
              {target.reasons.map((reason, index) => (
                <span key={index}>
                  {index > 0 && ' · '}
                  <span className={index === 0 ? 'text-on-surface font-medium' : ''}>{reason}</span>
                </span>
              ))}
              {target.temporal_insight && (
                <>
                  {' '}
                  · <span className="text-primary font-bold">{target.temporal_insight}</span>
                </>
              )}
            </p>
          </div>
        </div>

        <div className="col-span-12">
          <h3 className="text-sm font-bold text-on-surface uppercase tracking-widest border-b border-outline-variant/20 pb-4 mb-6">
            Risk Factor Breakdown
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {factors.map((factor) => (
              <React.Fragment key={factor.title}>
                <FactorCard {...factor} />
              </React.Fragment>
            ))}
          </div>
        </div>

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
                    <stop offset="5%" stopColor="#ffb4ab" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ffb4ab" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#424754" vertical={false} opacity={0.2} />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#8c909f', fontFamily: 'monospace' }} />
                <YAxis hide />
                <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }} itemStyle={{ fontSize: '11px', fontWeight: 'bold' }} />
                <Area type="monotone" dataKey="risk" stroke="#ffb4ab" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        </div>
      )}
    </div>
  );
}

function DecisionStep({ label, active, variant }: { label: string; active?: boolean; variant?: 'error' }) {
  return (
    <div
      className={cn(
        'flex-1 text-center py-2 rounded-lg font-mono text-[10px] font-bold uppercase tracking-widest transition-all',
        active ? (variant === 'error' ? 'bg-error text-on-error shadow-[0_0_15px_#ffb4ab]' : 'bg-primary text-on-primary') : 'text-on-surface-variant/40',
      )}
    >
      {active && <ShieldX size={12} className="inline mr-2 mb-0.5" />}
      {label}
    </div>
  );
}

function FactorCard({
  title,
  value,
  icon,
  status,
  percentage,
  color,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  status: string;
  percentage: number;
  color: 'error' | 'primary' | 'tertiary';
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
