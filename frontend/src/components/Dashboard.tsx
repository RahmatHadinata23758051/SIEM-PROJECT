import React, { useEffect, useRef } from 'react';
import { Activity, ShieldX, Target, Terminal, Zap } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis } from 'recharts';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import { formatLogLine } from '../lib/api';
import { useSIEMStream } from '../hooks/useSIEMStream';

export default function Dashboard() {
  const { events, metrics, telemetry, debug, isStreaming, setStreaming, clearEvents } = useSIEMStream();
  const streamRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = 0;
    }
  }, [events]);

  const statusVariant = metrics.status === 'CRITICAL' ? 'error' : metrics.status === 'ELEVATED' ? 'warning' : undefined;
  const trendLabel = metrics.events_trend >= 0 ? `+${metrics.events_trend}% vs previous window` : `${metrics.events_trend}% vs previous window`;

  const total = metrics.high_risk_count + metrics.elevated_anomaly_count + metrics.baseline_count;
  const pctHigh = total ? Math.round((metrics.high_risk_count / total) * 100) : 0;
  const pctElevated = total ? Math.round((metrics.elevated_anomaly_count / total) * 100) : 0;
  const pctBaseline = total ? Math.round((metrics.baseline_count / total) * 100) : 0;

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Dashboard Overview</h1>
          <p className="text-sm text-on-surface-variant mt-1">Real-time telemetry and active threat intelligence.</p>
        </div>
        <button
          onClick={() => setStreaming(!isStreaming)}
          className="flex items-center gap-2 text-on-surface-variant font-mono text-xs hover:text-on-surface transition-colors"
        >
          <span className={cn('w-2 h-2 rounded-full', isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-outline-variant')} />
          {isStreaming ? 'Live Sync' : 'Paused'}
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <MetricCard
          title="System Status"
          value={metrics.status}
          subtitle={metrics.status === 'CRITICAL' ? 'UNDER ATTACK' : metrics.status === 'ELEVATED' ? 'MONITORING' : 'ALL CLEAR'}
          icon={<ShieldX className="text-error w-10 h-10" />}
          variant={statusVariant}
        />
        <MetricCard
          title="Events Processed"
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
        <MetricCard
          title="Event Rate"
          value={`${debug.event_rate_per_sec.toFixed(3)}/s`}
          subtitle={`${debug.active_connections} ws clients`}
          icon={<Terminal className="text-tertiary w-10 h-10" />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 min-h-[400px]">
        <div className="lg:col-span-4 bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col">
          <div className="p-4 border-b border-outline-variant/30 flex justify-between items-center">
            <h3 className="font-semibold text-on-surface">Risk Distribution</h3>
            <div className="text-[10px] uppercase tracking-widest font-bold text-on-surface-variant">
              {debug.records_loaded} records
            </div>
          </div>
          <div className="p-6 flex flex-col gap-6">
            <RiskItem label="High Risk Nodes" percentage={pctHigh} count={metrics.high_risk_count} color="bg-error" />
            <RiskItem label="Elevated Anomalies" percentage={pctElevated} count={metrics.elevated_anomaly_count} color="bg-tertiary" />
            <RiskItem label="Baseline Operations" percentage={pctBaseline} count={metrics.baseline_count} color="bg-primary" />
          </div>
          <div className="mt-auto p-4 border-t border-outline-variant/30 h-40">
            <h4 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-2">Telemetry Volume</h4>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={telemetry}>
                <defs>
                  <linearGradient id="colorVol" x1="0" y1="0" x2="0" y2="100%">
                    <stop offset="5%" stopColor="#adc6ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#adc6ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" hide />
                <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', fontSize: '10px' }} />
                <Area type="monotone" dataKey="volume" stroke="#adc6ff" strokeWidth={2} fillOpacity={1} fill="url(#colorVol)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-8 bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col">
          <div className="p-4 border-b border-outline-variant/30 bg-surface-container-low/50 flex justify-between items-center">
            <h3 className="font-semibold text-on-surface flex items-center gap-2">
              <Terminal size={18} className="text-primary" />
              Live Event Stream
            </h3>
            <div className="flex items-center gap-2">
              <button
                onClick={clearEvents}
                className="text-[10px] font-bold text-on-surface-variant hover:text-error transition-colors uppercase tracking-widest px-2 py-0.5 rounded border border-outline-variant/30 hover:border-error/30"
              >
                Clear
              </button>
              <div className="bg-surface-container-highest px-2 py-0.5 rounded text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
                {isStreaming ? 'Live Stream' : 'Stream Paused'}
              </div>
            </div>
          </div>
          <div
            ref={streamRef}
            className="h-[450px] bg-surface-container-lowest/80 p-4 overflow-y-auto font-mono text-xs space-y-2 scrollbar-thin scrollbar-thumb-outline-variant/30 scrollbar-track-transparent"
          >
            {events.map((event) => {
              const line = formatLogLine(event);
              const isMultiVector = event.reasons.some(r => r.includes('Cross-source') || r.includes('Multi-vector'));
              return (
                <React.Fragment key={event.id}>
                  <LogEntry
                    time={line.time}
                    level={line.level}
                    message={line.message}
                    color={line.level === 'WARN' ? 'text-tertiary' : 'text-on-surface-variant'}
                    isCritical={line.level === 'CRIT'}
                    isMultiVector={isMultiVector}
                  />
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant,
}: {
  title: string;
  value: string;
  subtitle: string;
  icon: React.ReactNode;
  trend?: 'up' | 'down';
  variant?: 'error' | 'warning';
}) {
  return (
    <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col justify-between shadow-lg relative overflow-hidden group">
      {variant === 'error' && <div className="absolute top-0 right-0 w-32 h-32 bg-error/5 rounded-full -translate-y-1/2 translate-x-1/2 pointer-events-none" />}

      <div className="flex justify-between items-start z-10">
        <h3 className="text-sm font-semibold text-on-surface-variant uppercase tracking-wider">{title}</h3>
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
        <span className="text-on-surface-variant font-mono">
          {percentage}% ({count})
        </span>
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

function LogEntry({
  time,
  level,
  message,
  color = 'text-on-surface-variant',
  isCritical,
  isMultiVector,
}: {
  time: string;
  level: string;
  message: string;
  color?: string;
  isCritical?: boolean;
  isMultiVector?: boolean;
}) {
  return (
    <div className={cn('flex gap-4 px-2 py-1.5 rounded transition-all group cursor-default', isCritical ? 'bg-error/10 border border-error/20' : 'hover:bg-surface-container-highest/50')}>
      <span className="text-on-surface-variant/40 w-20 shrink-0 select-none">{time}</span>
      <span className={cn('shrink-0 w-12 font-bold', isCritical ? 'text-error' : 'text-primary')}>[{level}]</span>
      <span className={cn('break-all flex-1', isCritical ? 'font-medium' : color)}>
        {isMultiVector && <span className="inline-block mr-2 text-[8px] bg-tertiary text-on-tertiary px-1 py-0.5 rounded font-bold uppercase tracking-widest align-middle shadow-[0_0_5px_#ffb4ab]">Multi-Vector</span>}
        {message}
      </span>
    </div>
  );
}
