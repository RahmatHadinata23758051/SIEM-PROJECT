/**
 * src/hooks/useSIEMStream.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Shared hook — live-streaming SIEM events at configurable interval.
 * All components that need live data MUST use this hook.
 * ──────────────────────────────────────────────────────────────────────────────
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import {
  generateSIEMEvent,
  generateEventBatch,
  getSystemMetrics,
  getTelemetryHistory,
  type SIEMEvent,
  type SystemMetrics,
  type TelemetryPoint,
} from '../lib/api';

export interface SIEMStreamState {
  events: SIEMEvent[];
  metrics: SystemMetrics;
  telemetry: TelemetryPoint[];
  isStreaming: boolean;
  lastUpdated: Date | null;
  /** Manually pause / resume the stream */
  setStreaming: (v: boolean) => void;
  /** Force a full data refresh */
  refresh: () => void;
}

interface UseSIEMStreamOptions {
  /** Interval in ms between new events (default 2000) */
  intervalMs?: number;
  /** Max events to keep in buffer (default 50) */
  maxEvents?: number;
  /** Initial batch size (default 15) */
  initialBatch?: number;
  /** Auto-start streaming (default true) */
  autoStart?: boolean;
}

export function useSIEMStream(options: UseSIEMStreamOptions = {}): SIEMStreamState {
  const {
    intervalMs   = 2000,
    maxEvents    = 50,
    initialBatch = 15,
    autoStart    = true,
  } = options;

  const [events,      setEvents]      = useState<SIEMEvent[]>(() => generateEventBatch(initialBatch));
  const [metrics,     setMetrics]     = useState<SystemMetrics>(() => getSystemMetrics());
  const [telemetry,   setTelemetry]   = useState<TelemetryPoint[]>(() => getTelemetryHistory(12));
  const [isStreaming, setIsStreaming]  = useState(autoStart);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const tickRef = useRef(0);

  const refresh = useCallback(() => {
    setEvents(generateEventBatch(initialBatch));
    setMetrics(getSystemMetrics());
    setTelemetry(getTelemetryHistory(12));
    setLastUpdated(new Date());
  }, [initialBatch]);

  useEffect(() => {
    if (!isStreaming) return;

    const id = setInterval(() => {
      tickRef.current += 1;

      // New event every tick
      const newEvent = generateSIEMEvent();
      setEvents(prev => [newEvent, ...prev].slice(0, maxEvents));

      // Refresh metrics every 5 ticks (~10 s)
      if (tickRef.current % 5 === 0) {
        setMetrics(getSystemMetrics());
      }

      // Append a new telemetry point every 15 ticks (~30 s)
      if (tickRef.current % 15 === 0) {
        const now = new Date();
        const label = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
        setTelemetry(prev => [
          ...prev.slice(-11),
          { time: label, volume: Math.floor(Math.random() * 4500 + 1500), risk: Math.floor(Math.random() * 9000 + 800) },
        ]);
      }

      setLastUpdated(new Date());
    }, intervalMs);

    return () => clearInterval(id);
  }, [isStreaming, intervalMs, maxEvents]);

  return {
    events,
    metrics,
    telemetry,
    isStreaming,
    lastUpdated,
    setStreaming: setIsStreaming,
    refresh,
  };
}
