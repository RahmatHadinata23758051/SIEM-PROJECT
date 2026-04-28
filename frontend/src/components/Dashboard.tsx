import React, { useEffect, useRef } from 'react';
import { Shield, Activity, Target, Zap, MoreHorizontal, Terminal, ShieldX } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import { useSIEMStream } from '../hooks/useSIEMStream';
import { formatLogLine, type SIEMEvent } from '../lib/api';

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { events, metrics, telemetry, isStreaming, setStreaming } = useSIEMStream({
    intervalMs:   2000,
    maxEvents:    30,
    initialBatch: 12,
  });

  const streamRef = useRef<HTMLDivElement>(null);

  // Auto-scroll live stream to top (newest entry)
  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = 0;
    }
  }, [events]);

  const statusVariant = metrics.status === 'CRITICAL' ? 'error'
    : metrics.status === 'ELEVATED'  ? 'warning'
    : undefined;

  const trendLabel = metrics.events_trend >= 0
    ? `+${metrics.events_trend}% vs yesterday`
    : `${metrics.events_trend}% vs yesterday`;

  const total = metrics.high_risk_count + metrics.elevated_anomaly_count + metrics.baseline_count;
  const pctHigh     = total ? Math.round((metrics.high_risk_count          / total) * 100) : 8;
  const pctElevated = total ? Math.round((metrics.elevated_anomaly_count   / total) * 100) : 24;
  const pctBaseline = total ? Math.round((metrics.baseline_count           / total) * 100) : 68;

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      {/* Page Header */}
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Dashboard Overview</h1>
          <p className="text-sm text-on-surface-variant mt-1">Real-time telemetry and active threat intelligence.</p>
        </div>
        <button
          onClick={() => setStreaming(!isStreaming)}
          className="flex items-center gap-2 text-on-surface-variant font-mono text-xs hover:text-on-surface transition-colors"
        >
          <span className={cn(
            'w-2 h-2 rounded-full',
            isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-outline-variant'
          )} />
          {isStreaming ? 'Live Sync' : 'Paused'}
        </button>
      </header>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <MetricCard
          title="System Status"
          value={metrics.status}
          subtitle={metrics.status === 'CRITICAL' ? 'UNDER ATTACK' : metrics.status === 'ELEVATED' ? 'MONITORING' : 'ALL CLEAR'}
          icon={<ShieldX className="text-error w-10 h-10" />}
          variant={statusVariant}
        />
        <MetricCard
          title="Events Processed (24h)"
          value={metrics.events_24h}
          subtitle={trendLabel}
          icon={<Activity className="text-primary w-10 h-10" />}
          trend={metrics.events_trend >= 0 ? 'up' : 'down'}
        />
        <MetricCard
          title="Active Suspicious IPs"
          value={String(metrics.active_suspicious_ips)}
          subtitle={`${metrics.critical_nodes_isolated} critical nodes isolated`}
          icon={<Target className="text-error w-10 h-10" />}
          variant="warning"
        />
      </div>

      {/* Middle Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 min-h-[400px]">
        {/* Risk Distribution */}
        <div className="lg:col-span-4 bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col">
          <div className="p-4 border-b border-outline-variant/30 flex justify-between items-center">
            <h3 className="font-semibold text-on-surface">Risk Distribution</h3>
            <button className="text-on-surface-variant hover:text-on-surface transition-colors">
              <MoreHorizontal size={18} />
            </button>
          </div>
          <div className="p-6 flex-1 flex flex-col gap-8 justify-center">
            <RiskItem label="High Risk Nodes"      percentage={pctHigh}     count={metrics.high_risk_count}         color="bg-error" />
            <RiskItem label="Elevated Anomalies"   percentage={pctElevated} count={metrics.elevated_anomaly_count}  color="bg-tertiary" />
            <RiskItem label="Baseline Operations"  percentage={pctBaseline} count={metrics.baseline_count}          color="bg-primary" />
          </div>
        </div>

        {/* Live Event Stream */}
        <div className="lg:col-span-8 bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col">
          <div className="p-4 border-b border-outline-variant/30 bg-surface-container-low/50 flex justify-between items-center">
            <h3 className="font-semibold text-on-surface flex items-center gap-2">
              <Terminal size={18} className="text-primary" />
              Live Event Stream
            </h3>
            <div className="bg-surface-container-highest px-2 py-0.5 rounded text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
              {isStreaming ? 'Auto-Scroll On' : 'Stream Paused'}
            </div>
          </div>
          <div
            ref={streamRef}
            className="flex-1 bg-surface-container-lowest/80 p-4 overflow-y-auto font-mono text-xs space-y-2"
          >
            {events.map(event => {
              const line = formatLogLine(event);
              return (
                <LogEntry
                  key={event.id}
                  time={line.time}
                  level={line.level}
                  message={line.message}
                  color={line.level === 'WARN' ? 'text-tertiary' : 'text-on-surface-variant'}
                  isCritical={line.level === 'CRIT'}
                />
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Sub-components (layout & className unchanged) ────────────────────────────

function MetricCard({ title, value, subtitle, icon, trend, variant }: {
  title: string; value: string; subtitle: string; icon: React.ReactNode;
  trend?: 'up' | 'down'; variant?: 'error' | 'warning';
}) {
  return (
    <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col justify-between shadow-lg relative overflow-hidden group">
      {variant === 'error' && <div className="absolute top-0 right-0 w-32 h-32 bg-error/5 rounded-full -translate-y-1/2 translate-x-1/2 pointer-events-none" />}

      <div className="flex justify-between items-start z-10">
        <h3 className="text-sm font-semibold text-on-surface-variant uppercase tracking-wider">{title}</h3>
        <button className="text-on-surface-variant/50 hover:text-on-surface transition-colors">
          <MoreHorizontal size={16} />
        </button>
      </div>

      <div className="mt-8 flex items-end gap-6 z-10 transition-transform duration-300 group-hover:translate-x-1">
        <div>{icon}</div>
        <div>
          <div className={cn('text-3xl font-black tracking-tight', variant === 'error' ? 'text-error' : 'text-on-surface')}>{value}</div>
          <div className={cn('text-xs font-semibold mt-1', trend === 'up' ? 'text-primary flex items-center gap-1' : 'text-on-surface-variant')}>
            {trend === 'up' && <Zap size={12} className="fill-primary" />}
            {subtitle}
          </div>
        </div>
      </div>
    </div>
  );
}

function RiskItem({ label, percentage, count, color }: { label: string; percentage: number; count: number; color: string }) {
  return (
    <div>
      <div className="flex justify-between text-sm mb-2">
        <span className={cn('font-semibold', color.replace('bg-', 'text-'))}>{label}</span>
        <span className="text-on-surface-variant font-mono">{percentage}% ({count})</span>
      </div>
      <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 1, ease: 'easeOut' }}
          className={cn('h-full rounded-full', color)}
        />
      </div>
    </div>
  );
}

function LogEntry({ time, level, message, color = 'text-on-surface-variant', isCritical }: {
  time: string; level: string; message: string; color?: string; isCritical?: boolean;
}) {
  return (
    <div className={cn(
      'flex gap-4 px-2 py-1.5 rounded transition-all group cursor-default',
      isCritical ? 'bg-error/10 border border-error/20' : 'hover:bg-surface-container-highest/50',
    )}>
      <span className="text-on-surface-variant/40 w-20 shrink-0 select-none">{time}</span>
      <span className={cn('shrink-0 w-12 font-bold', isCritical ? 'text-error' : 'text-primary')}>[{level}]</span>
      <span className={cn('break-all', isCritical ? 'font-medium' : color)}>{message}</span>
    </div>
  );
}
