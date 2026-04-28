/**
 * src/hooks/useSIEMStream.tsx
 * ──────────────────────────────────────────────────────────────────────────────
 * Shared hook & context — live-streaming SIEM events globally.
 * ──────────────────────────────────────────────────────────────────────────────
 */
import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
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
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedIp: string | null;
  setSelectedIp: (ip: string | null) => void;
  setStreaming: (v: boolean) => void;
  refresh: () => void;
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
  const [metrics, setMetrics] = useState<SystemMetrics>(() => getSystemMetrics());
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>(() => getTelemetryHistory(12));
  const [isStreaming, setIsStreaming] = useState(autoStart);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

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
        const label = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
        setTelemetry(prev => [
          ...prev.slice(-11),
          { time: label, volume: Math.floor(Math.random() * 4500 + 1500), risk: Math.floor(Math.random() * 9000 + 800) },
        ]);
      }

      setLastUpdated(new Date());
    }, intervalMs);

    return () => clearInterval(id);
  }, [isStreaming, intervalMs, maxEvents]);

  return (
    <SIEMContext.Provider value={{ events, metrics, telemetry, isStreaming, lastUpdated, searchQuery, setSearchQuery, selectedIp, setSelectedIp, setStreaming: setIsStreaming, refresh }}>
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
