import React, { useEffect, useMemo, useState } from 'react';
import { Activity, BrainCircuit, Database, Globe, ShieldAlert, ShieldCheck, Users } from 'lucide-react';
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis } from 'recharts';
import { cn } from '../lib/utils';
import { fetchNetworkNodesAsync, type NetworkNode } from '../lib/api';
import { useSIEMStream } from '../hooks/useSIEMStream';

interface NetworkMapProps {
  onNavigate?: (view: string) => void;
}

export default function NetworkMap({ onNavigate }: NetworkMapProps) {
  const { events, telemetry, setSearchQuery, setSelectedIp } = useSIEMStream();
  const [fallbackNodes, setFallbackNodes] = useState<NetworkNode[]>([]);

  useEffect(() => {
    if (events.length > 0) return;
    let cancelled = false;
    fetchNetworkNodesAsync()
      .then((nodes) => {
        if (!cancelled) {
          setFallbackNodes(nodes);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFallbackNodes([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [events.length]);

  const nodes = useMemo(() => {
    if (events.length === 0) {
      return fallbackNodes;
    }

    const ipMap = new Map<string, { count: number; riskScores: number[]; action: string; level: string }>();

    for (const event of events) {
      if (!ipMap.has(event.ip)) {
        ipMap.set(event.ip, { count: 0, riskScores: [], action: event.action, level: event.risk_level });
      }
      const data = ipMap.get(event.ip)!;
      data.count += 1;
      data.riskScores.push(event.risk_score);
      if (event.risk_level === 'high' || (event.risk_level === 'medium' && data.level !== 'high')) {
        data.level = event.risk_level;
      }
      if (event.action === 'block' || (event.action === 'rate_limit' && data.action !== 'block')) {
        data.action = event.action;
      }
    }

    return Array.from(ipMap.entries())
      .map(([ip, data], index) => ({
        id: `node-${index}`,
        ip,
        risk_level: data.level as 'normal' | 'low' | 'medium' | 'high',
        risk_score: Math.round(data.riskScores.reduce((sum, value) => sum + value, 0) / data.riskScores.length),
        action: data.action as 'monitor' | 'rate_limit' | 'block',
        event_count: data.count,
        label: ip,
        country: 'UNK',
      }))
      .sort((left, right) => right.risk_score - left.risk_score);
  }, [events, fallbackNodes]);

  const volumeData = useMemo(
    () =>
      telemetry.map((point) => ({
        name: point.time,
        vol: point.volume,
        isAnomaly: point.risk >= 80,
      })),
    [telemetry],
  );

  const topEvent = useMemo(() => {
    if (events.length === 0) return undefined;
    return [...events].sort((left, right) => right.risk_score - left.risk_score)[0];
  }, [events]);

  const hasSpike = volumeData.some((item) => item.isAnomaly);

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Attack Visualization</h1>
          <p className="text-sm text-on-surface-variant mt-1">Live topology view driven by backend decisions and event telemetry.</p>
        </div>
        <div className="flex gap-2">
          <div className="h-9 px-4 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant text-xs font-bold uppercase tracking-wider">
            <Globe size={16} />
            Topology Snapshot
          </div>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-6 flex-1 min-h-[500px]">
        <div className="col-span-12 lg:col-span-8 bg-[#080B0E] border border-outline-variant/20 rounded-xl overflow-hidden relative group">
          <div
            className="absolute inset-0 opacity-10"
            style={{
              backgroundImage: 'linear-gradient(#424754 1px, transparent 1px), linear-gradient(90deg, #424754 1px, transparent 1px)',
              backgroundSize: '40px 40px',
            }}
          />

          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <Connection x1="20%" y1="30%" x2="40%" y2="50%" status="neutral" />
            <Connection x1="40%" y1="50%" x2="65%" y2="35%" status={topEvent?.risk_level === 'high' ? 'danger' : 'neutral'} animate />
            <Connection x1="65%" y1="35%" x2="85%" y2="55%" status={topEvent?.risk_level === 'high' ? 'danger' : 'neutral'} animate />
            <Connection x1="40%" y1="50%" x2="35%" y2="75%" status="neutral" />
          </svg>

          <MapNode
            x="20%"
            y="30%"
            icon={<Globe size={20} />}
            label={`Ext: ${nodes[0]?.ip ?? 'Awaiting data'}`}
            onClick={() => {
              if (nodes[0]?.ip) {
                setSearchQuery(nodes[0].ip);
                onNavigate?.('log-explorer');
              }
            }}
          />
          <MapNode
            x="40%"
            y="50%"
            icon={<Activity size={24} />}
            label={nodes[1]?.label ?? 'No data'}
            status={nodes[1]?.risk_level === 'high' ? 'danger' : undefined}
            isPulse={nodes[1]?.risk_level === 'high'}
            onClick={() => {
              if (nodes[1]?.ip) {
                setSearchQuery(nodes[1].ip);
                onNavigate?.('log-explorer');
              }
            }}
          />
          <MapNode
            x="65%"
            y="35%"
            icon={<Database size={20} />}
            label={nodes[2]?.label ?? 'No data'}
            status={nodes[2]?.risk_level === 'high' || nodes[2]?.risk_level === 'medium' ? 'danger' : undefined}
            onClick={() => {
              if (nodes[2]?.ip) {
                setSearchQuery(nodes[2].ip);
                onNavigate?.('log-explorer');
              }
            }}
          />
          <MapNode
            x="85%"
            y="55%"
            icon={<ShieldCheck size={20} />}
            label={nodes[3]?.label ?? 'No data'}
            status={nodes[3]?.risk_level === 'normal' ? 'success' : undefined}
            onClick={() => {
              if (nodes[3]?.ip) {
                setSearchQuery(nodes[3].ip);
                onNavigate?.('log-explorer');
              }
            }}
          />
          <MapNode
            x="35%"
            y="75%"
            icon={<Users size={20} />}
            label={nodes[4]?.label ?? 'No data'}
            onClick={() => {
              if (nodes[4]?.ip) {
                setSearchQuery(nodes[4].ip);
                onNavigate?.('log-explorer');
              }
            }}
          />

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

        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="bg-surface-container border border-outline-variant/30 rounded-xl flex flex-col flex-1 max-h-[300px]">
            <div className="p-4 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container-low/50">
              <h3 className="text-xs font-bold text-on-surface uppercase tracking-widest flex items-center gap-2">
                <Activity size={16} className="text-primary" />
                Volume Analysis
              </h3>
              <span className={cn('text-[10px] font-bold flex items-center gap-1', hasSpike ? 'text-error' : 'text-emerald-500')}>
                <ShieldAlert size={12} />
                {hasSpike ? 'Spike Detected' : 'Normal'}
              </span>
            </div>
            <div className="flex-1 p-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={volumeData}>
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#8c909f' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }} itemStyle={{ fontSize: '11px' }} />
                  <Bar dataKey="vol">
                    {volumeData.map((entry, index) => (
                      <Cell key={index} fill={entry.isAnomaly ? '#ffb4ab' : '#adc6ff33'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex-1 flex flex-col gap-4">
            <div className="flex items-center gap-3 border-b border-outline-variant/20 pb-4">
              <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                <BrainCircuit className="text-primary" size={20} />
              </div>
              <div>
                <h4 className="text-sm font-bold text-on-surface">{topEvent ? 'AI Pattern Confirmed' : 'Monitoring...'}</h4>
                <p className="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest">
                  {topEvent ? `${Math.round(topEvent.anomaly_score * 100)}% Confidence Match` : 'Awaiting data...'}
                </p>
              </div>
            </div>
            {topEvent && (
              <div className="space-y-3">
                <InsightMetric label="IP" value={topEvent.ip} />
                <InsightMetric label="Action" value={topEvent.action.toUpperCase()} />
                <InsightMetric label="Method" value={topEvent.scoring_method} />
                <InsightMetric
                  label="Deviation"
                  value={`${topEvent.risk_score.toFixed(1)} / 100`}
                  variant={topEvent.risk_level === 'high' ? 'error' : undefined}
                />
              </div>
            )}
            <button
              onClick={() => topEvent && setSelectedIp(topEvent.ip)}
              disabled={!topEvent}
              className="mt-auto w-full py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-[10px] font-bold uppercase tracking-widest hover:bg-surface-bright transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Investigate Chain
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function MapNode({
  x,
  y,
  icon,
  label,
  status,
  isPulse,
  onClick,
}: {
  x: string;
  y: string;
  icon: React.ReactNode;
  label: string;
  status?: 'danger' | 'success';
  isPulse?: boolean;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className="absolute flex flex-col items-center group cursor-pointer transition-transform hover:scale-110"
      style={{ left: x, top: y, transform: 'translate(-50%, -50%)' }}
    >
      <div
        className={cn(
          'w-12 h-12 rounded-full flex items-center justify-center bg-[#14191F] border-2 shadow-2xl relative z-10',
          status === 'danger'
            ? 'border-error text-error shadow-[0_0_20px_rgba(255,180,171,0.2)]'
            : status === 'success'
              ? 'border-emerald-500 text-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.1)]'
              : 'border-outline-variant text-on-surface-variant',
        )}
      >
        {isPulse && <span className="absolute inset-0 rounded-full bg-error animate-ping opacity-20" />}
        {icon}
      </div>
      <div className="mt-3 px-2 py-1 bg-surface-container-lowest/80 backdrop-blur-md border border-outline-variant/30 rounded text-[10px] font-mono whitespace-nowrap shadow-lg">
        {label}
      </div>
    </div>
  );
}

function Connection({
  x1,
  y1,
  x2,
  y2,
  status,
  animate,
}: {
  x1: string;
  y1: string;
  x2: string;
  y2: string;
  status: 'danger' | 'neutral';
  animate?: boolean;
}) {
  return (
    <line
      x1={x1}
      y1={y1}
      x2={x2}
      y2={y2}
      stroke={status === 'danger' ? '#ffb4ab' : '#424754'}
      strokeWidth={status === 'danger' ? '2' : '1.5'}
      strokeDasharray={status === 'neutral' ? '4 4' : '0'}
      className={cn(animate && 'animate-pulse')}
      opacity={status === 'neutral' ? 0.3 : 0.6}
    />
  );
}

function InsightMetric({ label, value, variant }: { label: string; value: string; variant?: 'error' }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-on-surface-variant font-mono">{label}</span>
      <span className={cn('font-bold text-right', variant === 'error' ? 'text-error' : 'text-on-surface')}>{value}</span>
    </div>
  );
}
