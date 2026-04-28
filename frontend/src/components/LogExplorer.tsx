import React, { useState } from 'react';
import { 
  Terminal, 
  Search, 
  ChevronDown, 
  Download, 
  Pause, 
  Play, 
  Filter, 
  Clock, 
  ShieldAlert,
  ChevronUp,
  ExternalLink,
  ShieldCheck,
  ShieldX
} from 'lucide-react';
import { cn } from '@/src/lib/utils';
import { motion, AnimatePresence } from 'motion/react';

interface Log {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
  sourceIp: string;
  destIp: string;
  message: string;
  details?: {
    riskScore: number;
    requestRate: string;
    variance: string;
    mitreTactic: string;
    payload: string;
  };
}

const logs: Log[] = [
  {
    id: '1',
    timestamp: '2023-10-27 14:32:01',
    severity: 'INFO',
    sourceIp: '192.168.1.45',
    destIp: '10.0.0.5',
    message: "User 'jdoe' successfully authenticated via SSO."
  },
  {
    id: '2',
    timestamp: '2023-10-27 14:32:04',
    severity: 'WARN',
    sourceIp: '172.16.0.102',
    destIp: '8.8.8.8',
    message: "High latency detected on primary outbound interface (eth0)."
  },
  {
    id: '3',
    timestamp: '2023-10-27 14:32:05',
    severity: 'CRITICAL',
    sourceIp: '185.15.22.90',
    destIp: '10.0.0.15',
    message: "Failed SSH login attempt for user 'root'. Signature match: Brute Force.",
    details: {
      riskScore: 98.5,
      requestRate: "45/sec",
      variance: "HIGH (New IP)",
      mitreTactic: "Credential Access",
      payload: JSON.stringify({
        "timestamp": "2023-10-27T14:32:05.112Z",
        "event_type": "ssh_auth",
        "src_ip": "185.15.22.90",
        "dest_ip": "10.0.0.15",
        "user": "root",
        "auth_method": "password",
        "result": "failure",
        "msg": "pam_unix(sshd:auth): authentication failure"
      }, null, 2)
    }
  },
  {
    id: '4',
    timestamp: '2023-10-27 14:32:08',
    severity: 'INFO',
    sourceIp: '10.0.0.15',
    destIp: '192.168.1.1',
    message: "Firewall rule 'Deny_All_Inbound' evaluated. Action: DROP."
  },
  {
    id: '5',
    timestamp: '2023-10-27 14:32:10',
    severity: 'INFO',
    sourceIp: '192.168.1.50',
    destIp: '10.0.0.2',
    message: "API requested resource /v1/metrics/health"
  }
];

export default function LogExplorer() {
  const [isStreaming, setIsStreaming] = useState(true);
  const [expandedLog, setExpandedLog] = useState<string | null>('3');

  return (
    <div className="flex flex-col h-full bg-background">
      {/* Header & Filters */}
      <div className="px-6 py-4 flex flex-col gap-4 border-b border-outline-variant/30 bg-surface-container-lowest/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-on-surface">Live Log Stream</h1>
            <div className="flex items-center gap-2 px-2 py-1 rounded-full bg-surface-container-high border border-outline-variant/30">
              <span className={cn("w-2 h-2 rounded-full", isStreaming ? "bg-primary animate-pulse" : "bg-outline-variant")} />
              <span className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
                {isStreaming ? 'Streaming' : 'Paused'}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setIsStreaming(!isStreaming)}
              className="h-9 px-3 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all text-sm font-semibold"
            >
              {isStreaming ? <Pause size={16} /> : <Play size={16} />}
              {isStreaming ? 'Pause Feed' : 'Resume Feed'}
            </button>
            <button className="h-9 px-3 flex items-center gap-2 rounded-lg bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-all text-sm font-semibold">
              <Download size={16} />
              Export
            </button>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center gap-2 bg-surface-container-low/50 p-1.5 rounded-xl border border-outline-variant/20 shadow-inner">
          <FilterGroup icon={<Clock size={16} />} label="Last 15 Minutes" />
          <FilterGroup icon={<ShieldAlert size={16} />} label="All Severities" />
          <div className="flex-1 flex items-center px-3 gap-3">
            <Terminal size={18} className="text-on-surface-variant" />
            <input 
              type="text" 
              placeholder="Filter by IP, host, or KQL query..." 
              className="bg-transparent border-none w-full text-sm font-mono text-on-surface focus:ring-0 placeholder-on-surface-variant/50"
            />
          </div>
        </div>
      </div>

      {/* Log Viewer Core */}
      <div className="flex-1 overflow-hidden flex flex-col p-4">
        {/* Table Header */}
        <div className="grid grid-cols-[160px_100px_140px_140px_1fr_40px] gap-4 px-6 py-3 bg-surface-container-high border border-outline-variant/30 rounded-t-xl text-[10px] font-bold text-on-surface-variant uppercase tracking-widest">
          <div>Timestamp</div>
          <div>Severity</div>
          <div>Source IP</div>
          <div>Dest IP</div>
          <div>Message Payload</div>
          <div className="text-center">Act</div>
        </div>

        {/* Scrolling Log Container */}
        <div className="flex-1 overflow-y-auto border-x border-b border-outline-variant/30 rounded-b-xl bg-surface-container-lowest/30">
          {logs.map((log) => (
            <div key={log.id} className="flex flex-col border-b border-outline-variant/10">
              <div 
                onClick={() => setExpandedLog(expandedLog === log.id ? null : log.id)}
                className={cn(
                  "grid grid-cols-[160px_100px_140px_140px_1fr_40px] gap-4 px-6 py-3 hover:bg-surface-container-low/50 transition-colors cursor-pointer group items-center font-mono text-xs",
                  log.severity === 'CRITICAL' ? "bg-error/5 text-on-surface" : "text-on-surface-variant",
                  expandedLog === log.id && log.severity === 'CRITICAL' && "bg-error/10"
                )}
              >
                <div className="text-[10px] opacity-60">{log.timestamp}</div>
                <div>
                  <span className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-bold border",
                    log.severity === 'INFO' ? "bg-primary/10 text-primary border-primary/20" :
                    log.severity === 'WARN' ? "bg-tertiary/10 text-tertiary border-tertiary/20" :
                    "bg-error/15 text-error border-error/30 animate-pulse"
                  )}>
                    {log.severity}
                  </span>
                </div>
                <div className={cn(log.severity === 'CRITICAL' ? "text-error font-bold" : "text-on-surface-variant")}>
                  {log.sourceIp}
                </div>
                <div>{log.destIp}</div>
                <div className="truncate font-medium">{log.message}</div>
                <div className="flex justify-center transition-opacity">
                  {expandedLog === log.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </div>
              </div>

              {/* Expansion Content */}
              <AnimatePresence>
                {expandedLog === log.id && log.details && (
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
                          <DetailItem label="risk_score" value={log.details.riskScore.toString()} variant="error" />
                          <DetailItem label="request_rate" value={log.details.requestRate} variant="tertiary" />
                          <DetailItem label="user_variance" value={log.details.variance} />
                          <DetailItem label="mitre_tactic" value={log.details.mitreTactic} />
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
                          <button className="px-3 py-1.5 rounded-lg border border-outline-variant/30 text-[10px] font-bold uppercase tracking-wider hover:bg-surface-container transition-colors">
                            View Timeline
                          </button>
                          <button className="px-3 py-1.5 rounded-lg bg-error/10 border border-error/40 text-error text-[10px] font-bold uppercase tracking-wider hover:bg-error/20 transition-colors">
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
        </div>
      </div>
    </div>
  );
}

function FilterGroup({ icon, label }: { icon: React.ReactNode, label: string }) {
  return (
    <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-surface-container-high transition-colors text-on-surface-variant text-sm font-medium border-r border-outline-variant/20 last:border-none">
      {icon}
      {label}
      <ChevronDown size={14} />
    </button>
  );
}

function DetailItem({ label, value, variant }: { label: string, value: string, variant?: 'error' | 'tertiary' }) {
  return (
    <div className="flex justify-between border-b border-outline-variant/10 pb-2">
      <span className="text-on-surface-variant">{label}:</span>
      <span className={cn(
        "font-bold",
        variant === 'error' ? "text-error" : variant === 'tertiary' ? "text-tertiary" : "text-on-surface"
      )}>{value}</span>
    </div>
  );
}
