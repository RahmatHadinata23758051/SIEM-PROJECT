/**
 * src/hooks/useSIEMStream.tsx
 * ──────────────────────────────────────────────────────────────────────────────
 * Shared hook & context — live-streaming SIEM events globally.
 * ──────────────────────────────────────────────────────────────────────────────
 */
import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import {
  generateEventBatch,
  fetchSystemMetricsAsync,
  getTelemetryHistory,
  createStreamManager,
  type SIEMEvent,
  type SystemMetrics,
  type TelemetryPoint,
} from '../lib/api';

export type ConnectionStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

export interface SIEMStreamState {
  events: SIEMEvent[];
  metrics: SystemMetrics;
  telemetry: TelemetryPoint[];
  isStreaming: boolean;
  lastUpdated: Date | null;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedIp: string | null;
  setSelectedIp: (ip: string | null) => void;
  setStreaming: (v: boolean) => void;
  refresh: () => void;
  clearEvents: () => void;
  connectionStatus: ConnectionStatus;
}

const SIEMContext = createContext<SIEMStreamState | null>(null);

interface SIEMProviderProps {
  children: React.ReactNode;
  intervalMs?: number;
  maxEvents?: number;
  initialBatch?: number;
  autoStart?: boolean;
}

export function SIEMProvider({
  children,
  intervalMs = 2000,
  maxEvents = 80,
  initialBatch = 20,
  autoStart = true,
}: SIEMProviderProps) {
  const [events, setEvents] = useState<SIEMEvent[]>(() => generateEventBatch(initialBatch));
  // Initial empty metrics will be updated by refresh()
  const [metrics, setMetrics] = useState<SystemMetrics>({
    status: 'NOMINAL', events_24h: '0', events_trend: 0, active_suspicious_ips: 0,
    critical_nodes_isolated: 0, high_risk_count: 0, elevated_anomaly_count: 0, baseline_count: 0
  });
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>(() => getTelemetryHistory(12));
  const [isStreaming, setIsStreaming] = useState(autoStart);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('CONNECTING');

  const wsRef = useRef<WebSocket | null>(null);
  const streamRef = useRef<any>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const newMetrics = await fetchSystemMetricsAsync();
      setMetrics(newMetrics);
    } catch (e) {
      console.error('[Stream] Metrics refresh error:', e);
    }
    setLastUpdated(new Date());
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  // Fetch initial metrics
  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!isStreaming) {
      if (streamRef.current) {
        streamRef.current.disconnect();
        streamRef.current = null;
      }
      setConnectionStatus('DISCONNECTED');
      return;
    }

    // Create new stream manager
    const stream = createStreamManager();
    streamRef.current = stream;

    // Subscribe to status changes
    const unsubscribeStatus = stream.onStatus((status) => {
      setConnectionStatus(status as ConnectionStatus);
    });

    // Subscribe to events
    const unsubscribeEvents = stream.onEvents((newEvents) => {
      setEvents((prev) => {
        const combined = [...newEvents, ...prev];
        return combined.slice(0, maxEvents);
      });

      refresh(); // Refresh metrics on new events

      // Update telemetry
      const now = new Date();
      const label = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      setTelemetry((prev) => {
        if (prev.length > 0 && prev[prev.length - 1].time === label) return prev;
        return [
          ...prev.slice(-11),
          {
            time: label,
            volume: Math.floor(Math.random() * 4500 + 1500),
            risk: Math.floor(Math.random() * 9000 + 800),
          },
        ];
      });

      setLastUpdated(new Date());
    });

    // Subscribe to errors
    const unsubscribeError = stream.onError((error) => {
      console.error('[Stream] Connection error:', error);
      setConnectionStatus('ERROR');
    });

    // Connect
    stream.connect();

    // Cleanup
    return () => {
      unsubscribeStatus();
      unsubscribeEvents();
      unsubscribeError();
      stream.disconnect();
      streamRef.current = null;
    };
  }, [isStreaming, maxEvents, refresh]);

  return (
    <SIEMContext.Provider value={{ events, metrics, telemetry, isStreaming, lastUpdated, searchQuery, setSearchQuery, selectedIp, setSelectedIp, setStreaming: setIsStreaming, refresh, clearEvents, connectionStatus }}>
      {children}
    </SIEMContext.Provider>
  );
}

export function useSIEMStream(options?: any): SIEMStreamState {
  const context = useContext(SIEMContext);
  if (!context) {
    throw new Error('useSIEMStream must be used within a SIEMProvider');
  }
  return context;
}
