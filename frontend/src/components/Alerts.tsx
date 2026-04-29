import React, { useEffect, useState, useMemo } from 'react';
import { ShieldAlert, CheckCircle, Clock, AlertTriangle, PlayCircle, Filter } from 'lucide-react';
import { cn } from '@/src/lib/utils';
import { Alert, fetchAllAlertsAsync, acknowledgeAlertAsync, resolveAlertAsync } from '../lib/api';

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'TRIGGERED' | 'ACKNOWLEDGED' | 'RESOLVED'>('ALL');

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const data = await fetchAllAlertsAsync(100);
      setAlerts(data.reverse()); // latest first
      setError(null);
    } catch (err) {
      setError('Failed to load alerts.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAcknowledge = async (id: string) => {
    const updated = await acknowledgeAlertAsync(id);
    if (updated) {
      setAlerts((prev) => prev.map((a) => (a.id === id ? updated : a)));
    }
  };

  const handleResolve = async (id: string) => {
    const updated = await resolveAlertAsync(id);
    if (updated) {
      setAlerts((prev) => prev.map((a) => (a.id === id ? updated : a)));
    }
  };

  const filteredAlerts = useMemo(() => {
    if (filter === 'ALL') return alerts;
    return alerts.filter((a) => a.state === filter);
  }, [alerts, filter]);

  const stats = useMemo(() => {
    return {
      triggered: alerts.filter((a) => a.state === 'TRIGGERED').length,
      acknowledged: alerts.filter((a) => a.state === 'ACKNOWLEDGED').length,
      resolved: alerts.filter((a) => a.state === 'RESOLVED').length,
      critical: alerts.filter((a) => a.severity === 'CRITICAL' && a.state !== 'RESOLVED').length,
    };
  }, [alerts]);

  return (
    <div className="h-full flex flex-col p-6 overflow-hidden">
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-on-surface">Alert Management</h1>
          <p className="text-sm text-on-surface-variant mt-1">Review and manage incident lifecycle from triggered to resolved.</p>
        </div>
        <div className="flex items-center gap-2">
          <FilterButton label="All" active={filter === 'ALL'} onClick={() => setFilter('ALL')} />
          <FilterButton label="Triggered" count={stats.triggered} active={filter === 'TRIGGERED'} onClick={() => setFilter('TRIGGERED')} tone="error" />
          <FilterButton label="Acknowledged" count={stats.acknowledged} active={filter === 'ACKNOWLEDGED'} onClick={() => setFilter('ACKNOWLEDGED')} tone="warn" />
          <FilterButton label="Resolved" count={stats.resolved} active={filter === 'RESOLVED'} onClick={() => setFilter('RESOLVED')} tone="success" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 shrink-0">
        <StatCard title="Active Critical" value={stats.critical.toString()} icon={<AlertTriangle size={20} />} tone="error" />
        <StatCard title="Triggered" value={stats.triggered.toString()} icon={<ShieldAlert size={20} />} tone="error" />
        <StatCard title="Acknowledged" value={stats.acknowledged.toString()} icon={<Clock size={20} />} tone="warn" />
        <StatCard title="Resolved" value={stats.resolved.toString()} icon={<CheckCircle size={20} />} tone="success" />
      </div>

      <div className="flex-1 bg-surface-container border border-outline-variant/30 rounded-xl overflow-hidden flex flex-col">
        {loading && alerts.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <span className="text-on-surface-variant font-medium">Loading alerts...</span>
          </div>
        ) : error ? (
          <div className="flex-1 flex items-center justify-center">
            <span className="text-error font-medium">{error}</span>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="flex-1 flex items-center justify-center flex-col gap-2">
            <CheckCircle size={48} className="text-emerald-500/50" />
            <span className="text-on-surface-variant font-medium">No alerts found.</span>
          </div>
        ) : (
          <div className="overflow-auto flex-1 p-4 space-y-3">
            {filteredAlerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                onAcknowledge={() => handleAcknowledge(alert.id)}
                onResolve={() => handleResolve(alert.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function FilterButton({ label, count, active, onClick, tone = 'default' }: { label: string; count?: number; active: boolean; onClick: () => void; tone?: 'default' | 'error' | 'warn' | 'success' }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all flex items-center gap-2 border',
        active
          ? tone === 'error'
            ? 'bg-error/20 text-error border-error/50'
            : tone === 'warn'
            ? 'bg-tertiary/20 text-tertiary border-tertiary/50'
            : tone === 'success'
            ? 'bg-emerald-500/20 text-emerald-500 border-emerald-500/50'
            : 'bg-primary/20 text-primary border-primary/50'
          : 'bg-surface-container-high text-on-surface-variant border-outline-variant/30 hover:bg-surface-container-highest hover:text-on-surface'
      )}
    >
      {label}
      {count !== undefined && (
        <span className={cn(
          'px-1.5 py-0.5 rounded text-[10px]',
          active ? 'bg-background/50' : 'bg-surface-container-low'
        )}>
          {count}
        </span>
      )}
    </button>
  );
}

function StatCard({ title, value, icon, tone }: { title: string; value: string; icon: React.ReactNode; tone: 'error' | 'warn' | 'success' }) {
  const tones = {
    error: 'text-error',
    warn: 'text-tertiary',
    success: 'text-emerald-500',
  };
  return (
    <div className="bg-surface-container-low border border-outline-variant/30 rounded-xl p-4 flex items-center gap-4">
      <div className={cn('w-12 h-12 rounded-full flex items-center justify-center bg-surface-container-highest', tones[tone])}>
        {icon}
      </div>
      <div>
        <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-widest">{title}</h3>
        <p className="text-2xl font-black text-on-surface mt-1">{value}</p>
      </div>
    </div>
  );
}

function AlertRow({ alert, onAcknowledge, onResolve }: { alert: Alert; onAcknowledge: () => void; onResolve: () => void }) {
  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-error border-error bg-error/10';
      case 'HIGH': return 'text-orange-500 border-orange-500 bg-orange-500/10';
      case 'MEDIUM': return 'text-tertiary border-tertiary bg-tertiary/10';
      case 'LOW': return 'text-primary border-primary bg-primary/10';
      default: return 'text-on-surface-variant border-outline-variant bg-surface-container';
    }
  };

  const getStateColor = (state: string) => {
    switch (state) {
      case 'TRIGGERED': return 'text-error border-error bg-error/10 animate-pulse';
      case 'ACKNOWLEDGED': return 'text-tertiary border-tertiary bg-tertiary/10';
      case 'RESOLVED': return 'text-emerald-500 border-emerald-500 bg-emerald-500/10';
      default: return 'text-on-surface-variant border-outline-variant bg-surface-container';
    }
  };

  return (
    <div className="bg-surface-container-high border border-outline-variant/30 rounded-xl p-4 flex flex-col md:flex-row gap-4 md:items-center hover:border-outline-variant transition-colors">
      <div className="flex-1 grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
        <div className="md:col-span-2 flex flex-col gap-1">
          <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">Severity</span>
          <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border self-start', getSeverityColor(alert.severity))}>
            {alert.severity}
          </span>
        </div>
        
        <div className="md:col-span-3 flex flex-col gap-1">
          <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">Target IP</span>
          <span className="font-mono text-sm font-bold text-on-surface">{alert.ip}</span>
        </div>

        <div className="md:col-span-4 flex flex-col gap-1">
          <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">Description</span>
          <span className="text-xs text-on-surface line-clamp-2" title={alert.description}>{alert.description}</span>
        </div>

        <div className="md:col-span-3 flex flex-col gap-1">
          <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">State</span>
          <div className="flex items-center gap-2">
            <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border', getStateColor(alert.state))}>
              {alert.state}
            </span>
            <span className="text-[10px] text-on-surface-variant whitespace-nowrap">
              {new Date(alert.updated_at).toLocaleTimeString('id-ID', { hour12: false })}
            </span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 border-t md:border-t-0 md:border-l border-outline-variant/20 pt-3 md:pt-0 md:pl-4">
        {alert.state === 'TRIGGERED' && (
          <button
            onClick={onAcknowledge}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-tertiary/10 text-tertiary border border-tertiary/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-tertiary/20 transition-colors"
          >
            <PlayCircle size={14} /> Ack
          </button>
        )}
        {alert.state !== 'RESOLVED' && (
          <button
            onClick={onResolve}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-emerald-500/20 transition-colors"
          >
            <CheckCircle size={14} /> Resolve
          </button>
        )}
      </div>
    </div>
  );
}
