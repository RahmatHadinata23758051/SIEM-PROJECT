import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  USE_REAL_API,
  type Action,
  type DebugStats,
  type ManualOverride,
  type SIEMEvent,
  type SystemMetrics,
  type TelemetryPoint,
  blockIpAsync,
  createStreamManager,
  enforcePolicyAsync,
  fetchDebugStatsAsync,
  fetchSystemMetricsAsync,
  fetchTelemetryAsync,
  generateEventBatch,
  getTelemetryHistory,
} from '../lib/api';

export type ConnectionStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

export interface SIEMStreamState {
  events: SIEMEvent[];
  metrics: SystemMetrics;
  telemetry: TelemetryPoint[];
  debug: DebugStats;
  isStreaming: boolean;
  lastUpdated: Date | null;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  selectedIp: string | null;
  setSelectedIp: (ip: string | null) => void;
  setStreaming: (value: boolean) => void;
  refresh: () => Promise<void>;
  clearEvents: () => void;
  connectionStatus: ConnectionStatus;
  blockIp: (ip: string, reason?: string) => Promise<void>;
  enforcePolicy: (ip: string, action: Action, reason?: string) => Promise<void>;
}

const EMPTY_METRICS: SystemMetrics = {
  status: 'NOMINAL',
  events_24h: '0',
  events_trend: 0,
  active_suspicious_ips: 0,
  critical_nodes_isolated: 0,
  high_risk_count: 0,
  elevated_anomaly_count: 0,
  baseline_count: 0,
};

const EMPTY_DEBUG: DebugStats = {
  backend_started_at: null,
  model_loaded: false,
  records_loaded: 0,
  parsed_events_loaded: 0,
  unique_ips: 0,
  active_connections: 0,
  total_connections: 0,
  total_disconnects: 0,
  total_batches_sent: 0,
  total_events_sent: 0,
  broadcast_errors: 0,
  stream_position: 0,
  last_batch_at: null,
  event_rate_per_sec: 0,
  latest_volume: 0,
  latest_risk: 0,
  decision_count: 0,
  manual_overrides: {},
};

const SIEMContext = createContext<SIEMStreamState | null>(null);

interface SIEMProviderProps {
  children: React.ReactNode;
  maxEvents?: number;
  initialBatch?: number;
  autoStart?: boolean;
}

function applyManualOverride(event: SIEMEvent, override: ManualOverride): SIEMEvent {
  const reasons = [
    `Manual policy override: ${override.action.toUpperCase()} (${override.reason})`,
    ...event.reasons.filter((reason) => !reason.startsWith('Manual policy override:')),
  ].slice(0, 10);

  if (override.action === 'block') {
    return {
      ...event,
      action: 'block',
      risk_level: 'high',
      risk_score: Math.max(event.risk_score, 95),
      reasons,
      manual_override: override,
    };
  }

  if (override.action === 'rate_limit') {
    return {
      ...event,
      action: 'rate_limit',
      risk_level: event.risk_level === 'high' ? 'high' : 'medium',
      risk_score: Math.max(event.risk_score, 70),
      reasons,
      manual_override: override,
    };
  }

  return {
    ...event,
    action: 'monitor',
    reasons,
    manual_override: override,
  };
}

export function SIEMProvider({
  children,
  maxEvents = 100,
  initialBatch = 20,
  autoStart = true,
}: SIEMProviderProps) {
  const [events, setEvents] = useState<SIEMEvent[]>(() => (USE_REAL_API ? [] : generateEventBatch(initialBatch)));
  const [metrics, setMetrics] = useState<SystemMetrics>(EMPTY_METRICS);
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>(() => (USE_REAL_API ? [] : getTelemetryHistory(12)));
  const [debug, setDebug] = useState<DebugStats>(EMPTY_DEBUG);
  const [isStreaming, setIsStreaming] = useState(autoStart);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('CONNECTING');

  const refresh = useCallback(async () => {
    const [nextMetrics, nextTelemetry, nextDebug] = await Promise.all([
      fetchSystemMetricsAsync(),
      fetchTelemetryAsync(),
      fetchDebugStatsAsync(),
    ]);
    setMetrics(nextMetrics);
    setTelemetry(nextTelemetry);
    setDebug(nextDebug);
    setLastUpdated(new Date());
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const patchEventsForOverride = useCallback((ip: string, override: ManualOverride) => {
    setEvents((prev) => prev.map((event) => (event.ip === ip ? applyManualOverride(event, override) : event)));
  }, []);

  const blockIp = useCallback(async (ip: string, reason = 'Blocked from dashboard') => {
    await blockIpAsync(ip, reason);
    patchEventsForOverride(ip, {
      action: 'block',
      reason,
      source: 'frontend',
      created_at: new Date().toISOString(),
    });
    await refresh();
  }, [patchEventsForOverride, refresh]);

  const enforcePolicy = useCallback(async (ip: string, action: Action, reason = 'Policy enforced from dashboard') => {
    await enforcePolicyAsync(ip, action, reason);
    patchEventsForOverride(ip, {
      action,
      reason,
      source: 'frontend',
      created_at: new Date().toISOString(),
    });
    await refresh();
  }, [patchEventsForOverride, refresh]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!isStreaming) {
      setConnectionStatus('DISCONNECTED');
      return;
    }

    const stream = createStreamManager();

    const unsubscribeStatus = stream.onStatus((status) => {
      setConnectionStatus(status as ConnectionStatus);
    });

    const unsubscribeEvents = stream.onEvents((incomingEvents) => {
      setEvents((prev) => {
        const merged = new Map<string, SIEMEvent>();

        for (const event of incomingEvents) {
          merged.set(event.id, event);
        }
        for (const event of prev) {
          if (!merged.has(event.id)) {
            merged.set(event.id, event);
          }
        }

        return Array.from(merged.values()).slice(0, maxEvents);
      });

      void refresh();
      setLastUpdated(new Date());
    });

    const unsubscribeError = stream.onError((error) => {
      console.error('[Stream] Connection error:', error);
      setConnectionStatus('ERROR');
    });

    stream.connect();

    return () => {
      unsubscribeStatus();
      unsubscribeEvents();
      unsubscribeError();
      stream.disconnect();
    };
  }, [isStreaming, maxEvents, refresh]);

  return (
    <SIEMContext.Provider
      value={{
        events,
        metrics,
        telemetry,
        debug,
        isStreaming,
        lastUpdated,
        searchQuery,
        setSearchQuery,
        selectedIp,
        setSelectedIp,
        setStreaming: setIsStreaming,
        refresh,
        clearEvents,
        connectionStatus,
        blockIp,
        enforcePolicy,
      }}
    >
      {children}
    </SIEMContext.Provider>
  );
}

export function useSIEMStream(): SIEMStreamState {
  const context = useContext(SIEMContext);
  if (!context) {
    throw new Error('useSIEMStream must be used within a SIEMProvider');
  }
  return context;
}
