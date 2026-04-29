import React, { useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Download,
  Pause,
  Play,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { cn } from '../lib/utils';
import { type SIEMEvent } from '../lib/api';
import { useSIEMStream } from '../hooks/useSIEMStream';

type Severity = 'ALL' | 'INFO' | 'WARN' | 'CRIT';

interface Log {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'WARN' | 'CRIT';
  sourceIp: string;
  message: string;
  details: {
    riskScore: number;
    requestRate: string;
    variance: string;
    reasons: string[];
    payload: string;
  };
}

function toLog(event: SIEMEvent): Log {
  const severityMap: Record<string, 'INFO' | 'WARN' | 'CRIT'> = {
    normal: 'INFO',
    low: 'INFO',
    medium: 'WARN',
    high: 'CRIT',
  };

  return {
    id: event.id,
    timestamp: new Date(event.timestamp).toLocaleString('id-ID', { hour12: false }),
    severity: severityMap[event.risk_level],
    sourceIp: event.ip,
    message: `[SSH] ${event.action.toUpperCase()} - risk=${event.risk_score.toFixed(0)} rule=${event.rule_score} anomaly=${event.anomaly_score.toFixed(2)} | ${event.reasons[0] ?? 'No anomalies'}`,
    details: {
      riskScore: event.risk_score,
      requestRate: `${event.request_rate.toFixed(3)}/s`,
      variance: `${event.username_variance} unique users`,
      reasons: event.reasons,
      payload: JSON.stringify(
        {
          timestamp: event.timestamp,
          event_type: 'ssh_auth',
          src_ip: event.ip,
          risk_score: event.risk_score,
          rule_score: event.rule_score,
          anomaly: event.anomaly_score,
          action: event.action,
          method: event.scoring_method,
          failed_count: event.failed_count,
          failed_ratio: event.failed_ratio,
          strike_count: event.strike_count,
          manual_override: event.manual_override,
          reasons: event.reasons,
        },
        null,
        2,
      ),
    },
  };
}

export default function LogExplorer() {
  const {
    events,
    isStreaming,
    setStreaming,
    searchQuery,
    setSearchQuery,
    setSelectedIp,
    blockIp,
  } = useSIEMStream();

  const [expandedLog, setExpandedLog] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity>('ALL');
  const [page, setPage] = useState(1);
  const itemsPerPage = 15;

  const logs = useMemo(() => events.map(toLog), [events]);

  useEffect(() => {
    setPage(1);
  }, [searchQuery, severity]);

  const filtered = useMemo(() => {
    return logs.filter((log) => {
      const matchSeverity = severity === 'ALL' || log.severity === severity;
      const query = searchQuery.toLowerCase();
      const matchQuery =
        !query ||
        log.sourceIp.includes(query) ||
        log.message.toLowerCase().includes(query) ||
        log.severity.toLowerCase().includes(query);
      return matchSeverity && matchQuery;
    });
  }, [logs, searchQuery, severity]);

  const paginatedLogs = useMemo(() => filtered.slice(0, page * itemsPerPage), [filtered, page]);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `siem-logs-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full bg-background">
      <div className="px-6 py-4 flex flex-col gap-4 border-b border-outline-variant/30 bg-surface-container-lowest/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-on-surface">Live Log Stream</h1>
            <div className="flex items-center gap-2 px-2 py-1 rounded-full bg-surface-container-high border border-outline-variant/30">
              <span className={cn('w-2 h-2 rounded-full', isStreaming ? 'bg-primary animate-pulse' : 'bg-outline-variant')} />
              <span className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                {isStreaming ? `Streaming · ${filtered.length} events` : 'Paused'}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setStreaming(!isStreaming)}
              className="h-9 px-3 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all text-sm font-semibold"
            >
              {isStreaming ? <Pause size={16} /> : <Play size={16} />}
              {isStreaming ? 'Pause Feed' : 'Resume Feed'}
            </button>
            <button
              onClick={handleExport}
              className="h-9 px-3 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all text-sm font-semibold"
            >
              <Download size={16} />
              Export
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-surface-container-low/50 p-1.5 rounded-xl border border-outline-variant/20 shadow-inner">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-on-surface-variant text-sm font-medium border-r border-outline-variant/20">
            <Terminal size={16} />
            Live
          </div>
          {(['ALL', 'INFO', 'WARN', 'CRIT'] as Severity[]).map((item) => (
            <button
              key={item}
              onClick={() => setSeverity(item)}
              className={cn(
                'flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all',
                severity === item ? 'bg-surface-container-highest text-on-surface' : 'text-on-surface-variant hover:bg-surface-container-high',
              )}
            >
              <ShieldAlert size={14} />
              {item}
            </button>
          ))}
          <div className="flex-1 flex items-center px-3 gap-3">
            <Terminal size={18} className="text-on-surface-variant" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Filter by IP, severity, or message..."
              className="bg-transparent border-none w-full text-sm font-mono text-on-surface focus:ring-0 placeholder-on-surface-variant/50 outline-none"
            />
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-hidden flex flex-col p-4">
        <div className="grid grid-cols-[180px_90px_150px_1fr_40px] gap-4 px-6 py-3 bg-surface-container-high border border-outline-variant/30 rounded-t-xl text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
          <div>Timestamp</div>
          <div>Severity</div>
          <div>Source IP</div>
          <div>Message Payload</div>
          <div className="text-center">Act</div>
        </div>

        <div className="flex-1 overflow-y-auto border-x border-b border-outline-variant/30 rounded-b-xl bg-surface-container-lowest/30">
          {filtered.length === 0 && (
            <div className="flex items-center justify-center h-32 text-on-surface-variant text-sm">No events match your filter.</div>
          )}
          {paginatedLogs.map((log) => (
            <div key={log.id} className="flex flex-col border-b border-outline-variant/10">
              <div
                onClick={() => setExpandedLog(expandedLog === log.id ? null : log.id)}
                className={cn(
                  'grid grid-cols-[180px_90px_150px_1fr_40px] gap-4 px-6 py-3 hover:bg-surface-container-low/50 transition-colors cursor-pointer items-center font-mono text-xs',
                  log.severity === 'CRIT' ? 'bg-error/5 text-on-surface' : 'text-on-surface-variant',
                  expandedLog === log.id && log.severity === 'CRIT' && 'bg-error/10',
                )}
              >
                <div className="text-[10px] opacity-60">{log.timestamp}</div>
                <div>
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-bold border',
                      log.severity === 'INFO'
                        ? 'bg-primary/10 text-primary border-primary/20'
                        : log.severity === 'WARN'
                          ? 'bg-tertiary/10 text-tertiary border-tertiary/20'
                          : 'bg-error/15 text-error border-error/30 animate-pulse',
                    )}
                  >
                    {log.severity}
                  </span>
                </div>
                <div
                  className={cn(log.severity === 'CRIT' ? 'text-error font-bold' : 'text-on-surface-variant', 'hover:underline cursor-pointer')}
                  onClick={(event) => {
                    event.stopPropagation();
                    setSelectedIp(log.sourceIp);
                  }}
                >
                  {log.sourceIp}
                </div>
                <div className="truncate font-medium">{log.message}</div>
                <div className="flex justify-center">{expandedLog === log.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}</div>
              </div>

              <AnimatePresence>
                {expandedLog === log.id && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden bg-surface-container-high/30 border-t border-outline-variant/10"
                  >
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-4">
                        <h4 className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                          <ShieldCheck size={14} className="text-primary" />
                          AI Parsed Features
                        </h4>
                        <div className="font-mono text-xs space-y-2">
                          <DetailItem label="risk_score" value={log.details.riskScore.toFixed(1)} variant={log.details.riskScore >= 85 ? 'error' : 'tertiary'} />
                          <DetailItem label="request_rate" value={log.details.requestRate} variant="tertiary" />
                          <DetailItem label="user_variance" value={log.details.variance} />
                          {log.details.reasons.map((reason, index) => (
                            <React.Fragment key={index}>
                              <DetailItem label={`reason[${index}]`} value={reason} />
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                      <div className="space-y-4">
                        <h4 className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
                          <Terminal size={14} className="text-on-surface-variant" />
                          Raw JSON Payload
                        </h4>
                        <pre className="p-3 bg-surface-container-lowest rounded-lg border border-outline-variant/20 text-[11px] text-on-surface-variant overflow-x-auto">
                          {log.details.payload}
                        </pre>
                        <div className="flex justify-end gap-2 pt-2">
                          <button
                            onClick={() => setSelectedIp(log.sourceIp)}
                            className="px-3 py-1.5 rounded-lg border border-outline-variant/30 text-[10px] font-bold uppercase tracking-wider hover:bg-surface-container transition-colors"
                          >
                            View Timeline
                          </button>
                          <button
                            onClick={() => void blockIp(log.sourceIp, 'Blocked from Log Explorer')}
                            className="px-3 py-1.5 rounded-lg bg-error/10 border border-error/40 text-error text-[10px] font-bold uppercase tracking-wider hover:bg-error/20 transition-colors"
                          >
                            Block IP
                          </button>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
          {paginatedLogs.length < filtered.length && (
            <div className="p-4 flex justify-center">
              <button
                onClick={() => setPage((current) => current + 1)}
                className="px-6 py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-surface-container-highest transition-colors"
              >
                Load More Events
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailItem({ label, value, variant }: { label: string; value: string; variant?: 'error' | 'tertiary' }) {
  return (
    <div className="flex justify-between border-b border-outline-variant/10 pb-2">
      <span className="text-on-surface-variant">{label}:</span>
      <span className={cn('font-bold text-right max-w-[60%] truncate', variant === 'error' ? 'text-error' : variant === 'tertiary' ? 'text-tertiary' : 'text-on-surface')}>
        {value}
      </span>
    </div>
  );
}
