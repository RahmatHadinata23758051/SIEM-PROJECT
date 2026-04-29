/**
 * src/lib/api.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Aegis AI SIEM — Central Data Layer (Dual-Mode: Real API + Mock Fallback)
 *
 * Mode Toggle:
 *  - USE_REAL_API = true: Consume from http://localhost:8001/api/*
 *  - USE_REAL_API = false: Use mock data generators
 *
 * Rules:
 *  - ALL data must conform to SIEMEvent interface
 *  - Mirrors PipelineDecision from hybrid_siem/pipeline.py
 *  - WebSocket for streaming, REST for historical data
 * ──────────────────────────────────────────────────────────────────────────────
 */

// ═══════════════════════════════════════════════════════════════════════════════
// MODE TOGGLE
// ═══════════════════════════════════════════════════════════════════════════════
export const USE_REAL_API = true;
export const API_BASE_URL = "http://127.0.0.1:8001";

// ─── Data Contracts ───────────────────────────────────────────────────────────

export type RiskLevel = 'normal' | 'low' | 'medium' | 'high';
export type Action    = 'monitor' | 'rate_limit' | 'block';
export type ScoringMethod = 'linear' | 'adaptive' | 'boosted' | 'sigmoid';
export type LogSeverity = 'INFO' | 'WARN' | 'CRIT' | 'DEBUG';

/** Mirrors PipelineDecision in hybrid_siem/pipeline.py */
export interface SIEMEvent {
  id: string;
  timestamp: string;        // ISO-8601
  ip: string;
  rule_score: number;       // 0–100
  anomaly_score: number;    // 0.0–1.0
  raw_anomaly_score: number;
  risk_score: number;       // 0–100 (watchlist current)
  risk_level: RiskLevel;
  action: Action;
  reasons: string[];
  scoring_method: ScoringMethod;
  temporal_insight: string;
  // Feature record fields
  failed_count: number;
  request_rate: number;
  username_variance: number;
  failed_ratio: number;
  event_count: number;
  total_attempts?: number;
  // Watchlist
  strike_count: number;
  repeat_incidents: number;
  adaptive_sensitivity: number;
}

export interface SystemMetrics {
  status: 'NOMINAL' | 'ELEVATED' | 'CRITICAL';
  events_24h: string;
  events_trend: number;         // percentage vs yesterday
  active_suspicious_ips: number;
  critical_nodes_isolated: number;
  high_risk_count: number;
  elevated_anomaly_count: number;
  baseline_count: number;
}

export interface TelemetryPoint {
  time: string;
  volume: number;
  risk: number;
}

export interface NetworkNode {
  id: string;
  ip: string;
  risk_level: RiskLevel;
  risk_score: number;
  action: Action;
  event_count: number;
  label?: string;
  country?: string;
}

export interface HuntingResult {
  ip: string;
  rule_score: number;
  anomaly_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  action: Action;
  strike_count: number;
  scoring_method: ScoringMethod;
  reasons: string[];
  temporal_insight: string;
  first_seen: string;
  last_seen: string;
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

let _seq = 0;
const uid = () => `evt-${Date.now()}-${++_seq}`;

const SUSPICIOUS_IPS = [
  '203.0.113.45', '185.220.101.12', '45.33.32.156', '198.51.100.77',
  '91.108.4.200',  '162.158.92.10',  '104.21.16.35',  '172.67.200.4',
  '77.88.55.60',   '8.8.8.8', '185.15.58.22', '210.10.5.44',
];

const COUNTRIES = ['RU', 'CN', 'US', 'KR', 'DE', 'NL', 'BR', 'ID', 'IN', 'UA'];

const REASON_POOL: Record<RiskLevel, string[]> = {
  normal: ['No anomalies detected', 'Baseline traffic pattern'],
  low:    ['Low rule score: 35', 'Minimal failed attempts detected'],
  medium: [
    'Medium rule score: 58', 'Failed attempts: 6', 'High request rate: 0.091',
    'Anomalous pattern detected: 0.621', 'Repeat offender: 2 strikes recorded',
  ],
  high: [
    'High rule score: 87', 'Failed attempts: 14', 'High request rate: 0.145',
    'High failed ratio: 0.92', 'Anomalous pattern detected: 0.872',
    'Non-linear boost applied (rule + anomaly agreement)',
    'Repeat offender: 4 strikes recorded', 'BLOCKED: High risk status',
    'Sustained activity: 11 events in window', 'Low username diversity: 1 unique users',
  ],
};

const rand  = (min: number, max: number) => Math.random() * (max - min) + min;
const randI = (min: number, max: number) => Math.floor(rand(min, max));
const pick  = <T>(arr: T[]): T => arr[randI(0, arr.length)];

function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 85) return 'high';
  if (score >= 65) return 'medium';
  if (score >= 40) return 'low';
  return 'normal';
}

function actionFromLevel(level: RiskLevel): Action {
  if (level === 'high')   return 'block';
  if (level === 'medium') return 'rate_limit';
  return 'monitor';
}

function isoNow(): string {
  return new Date().toISOString();
}

function timeLabel(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}.${String(d.getMilliseconds()).slice(0,2)}`;
}

// ─── Data Normalization (CRITICAL) ────────────────────────────────────────────

/**
 * Normalize and validate a SIEMEvent from backend.
 * Ensures all values are within expected bounds.
 */
export function normalizeSIEMEvent(event: any): SIEMEvent {
  // Clamp risk_score to 0-100
  const risk_score = Math.max(0, Math.min(100, parseFloat(event.risk_score) || 0));
  
  // Clamp anomaly_score to 0-1
  const anomaly_score = Math.max(0, Math.min(1, parseFloat(event.anomaly_score) || 0));
  const raw_anomaly_score = Math.max(0, Math.min(1, parseFloat(event.raw_anomaly_score) || anomaly_score));
  
  // Validate enum values
  const validRiskLevels: RiskLevel[] = ['normal', 'low', 'medium', 'high'];
  const risk_level: RiskLevel = validRiskLevels.includes(event.risk_level) ? event.risk_level : riskLevelFromScore(risk_score);
  
  const validActions: Action[] = ['monitor', 'rate_limit', 'block'];
  const action: Action = validActions.includes(event.action) ? event.action : actionFromLevel(risk_level);
  
  const validScoringMethods: ScoringMethod[] = ['linear', 'adaptive', 'boosted', 'sigmoid'];
  const scoring_method: ScoringMethod = validScoringMethods.includes(event.scoring_method) ? event.scoring_method : 'linear';
  
  // Clamp feature values
  const failed_count = Math.max(0, Math.floor(event.failed_count) || 0);
  const request_rate = Math.max(0, parseFloat(event.request_rate) || 0);
  const username_variance = Math.max(0, Math.floor(event.username_variance) || 0);
  const failed_ratio = Math.max(0, Math.min(1, parseFloat(event.failed_ratio) || 0));
  const event_count = Math.max(0, Math.floor(event.event_count) || 0);
  const strike_count = Math.max(0, Math.floor(event.strike_count) || 0);
  const repeat_incidents = Math.max(0, Math.floor(event.repeat_incidents) || 0);
  const adaptive_sensitivity = Math.max(1, Math.min(3, parseFloat(event.adaptive_sensitivity) || 1));
  
  // Ensure ID and timestamp exist
  const id = event.id || `evt-${Date.now()}-${Math.random()}`;
  const timestamp = event.timestamp || new Date().toISOString();
  const ip = event.ip || '0.0.0.0';
  
  // Parse reasons (ensure array)
  const reasons = Array.isArray(event.reasons) ? event.reasons.filter(r => typeof r === 'string').slice(0, 10) : [];
  const temporal_insight = (typeof event.temporal_insight === 'string') ? event.temporal_insight : '';
  
  // Rule score (0-100)
  const rule_score = Math.max(0, Math.min(100, parseFloat(event.rule_score) || 0));
  
  return {
    id,
    timestamp,
    ip,
    rule_score,
    anomaly_score,
    raw_anomaly_score,
    risk_score,
    risk_level,
    action,
    reasons,
    scoring_method,
    temporal_insight,
    failed_count,
    request_rate,
    username_variance,
    failed_ratio,
    event_count,
    total_attempts: event.total_attempts ? Math.max(0, Math.floor(event.total_attempts)) : undefined,
    strike_count,
    repeat_incidents,
    adaptive_sensitivity,
  };
}

// ─── Public Generators ────────────────────────────────────────────────────────

/** Generate a single realistic SIEM event (mirrors pipeline output). */
export function generateSIEMEvent(overrides?: Partial<SIEMEvent>): SIEMEvent {
  const ruleScore    = randI(0, 100);
  const anomalyRaw   = parseFloat(rand(0, 1).toFixed(3));
  const anomaly      = parseFloat(Math.min(1, anomalyRaw * (0.8 + Math.random() * 0.4)).toFixed(3));
  const riskScore    = parseFloat(rand(0, 100).toFixed(1));
  const level        = riskLevelFromScore(riskScore);
  const action       = actionFromLevel(level);
  const strikeCount  = randI(0, 6);
  const reasons      = [...REASON_POOL[level]].slice(0, randI(1, Math.min(4, REASON_POOL[level].length)));

  return {
    id: uid(),
    timestamp: isoNow(),
    ip: pick(SUSPICIOUS_IPS),
    rule_score: ruleScore,
    anomaly_score: anomaly,
    raw_anomaly_score: anomalyRaw,
    risk_score: riskScore,
    risk_level: level,
    action,
    reasons,
    scoring_method: pick(['linear','adaptive','boosted','sigmoid'] as ScoringMethod[]),
    temporal_insight: riskScore >= 65
      ? pick(['High event concentration in single window', 'Patterns of recurring attacks detected', ''])
      : '',
    failed_count: randI(0, 20),
    request_rate: parseFloat(rand(0, 0.2).toFixed(3)),
    username_variance: randI(1, 8),
    failed_ratio: parseFloat(rand(0, 1).toFixed(2)),
    event_count: randI(1, 15),
    strike_count: strikeCount,
    repeat_incidents: randI(0, 4),
    adaptive_sensitivity: parseFloat(rand(1, 2.5).toFixed(2)),
    ...overrides,
  };
}

/** Generate a batch of events (for initial load). */
export function generateEventBatch(count = 20): SIEMEvent[] {
  return Array.from({ length: count }, () => generateSIEMEvent());
}

/** Generate current system-wide metrics. */
export function getSystemMetrics(): SystemMetrics {
  const high      = randI(15, 45);
  const elevated  = randI(60, 110);
  const baseline  = randI(180, 280);
  const total     = high + elevated + baseline;
  const riskScore = (high / total) * 100;

  return {
    status:                 riskScore > 10 ? (riskScore > 15 ? 'CRITICAL' : 'ELEVATED') : 'NOMINAL',
    events_24h:             `${(randI(900, 1400) / 1000).toFixed(2)}B`,
    events_trend:           parseFloat(rand(-5, 25).toFixed(1)),
    active_suspicious_ips:  total,
    critical_nodes_isolated: high,
    high_risk_count:         high,
    elevated_anomaly_count:  elevated,
    baseline_count:          baseline,
  };
}

/** Generate telemetry chart points (last N hours). */
export function getTelemetryHistory(hours = 12): TelemetryPoint[] {
  const now = new Date();
  return Array.from({ length: hours }, (_, i) => {
    const t = new Date(now.getTime() - (hours - 1 - i) * 3600_000);
    const label = `${String(t.getHours()).padStart(2,'0')}:00`;
    return {
      time:   label,
      volume: randI(1500, 6000),
      risk:   randI(800, 9800),
    };
  });
}

/** Generate network node data for the Network Map. */
export function getNetworkNodes(count = 16): NetworkNode[] {
  return Array.from({ length: count }, (_, i) => {
    const score = parseFloat(rand(0, 100).toFixed(1));
    const level = riskLevelFromScore(score);
    const ip    = pick(SUSPICIOUS_IPS);
    return {
      id:          `node-${i}`,
      ip,
      risk_level:  level,
      risk_score:  score,
      action:      actionFromLevel(level),
      event_count: randI(1, 50),
      label:       `Node-${String(i+1).padStart(2,'0')}`,
      country:     pick(COUNTRIES),
    };
  });
}

/** Generate hunting results for ThreatHunting view. */
export function getHuntingResults(count = 10): HuntingResult[] {
  return Array.from({ length: count }, () => {
    const event   = generateSIEMEvent();
    const base    = new Date(Date.now() - randI(3600_000, 86400_000 * 3));
    const last    = new Date(base.getTime() + randI(60_000, 3600_000));
    return {
      ip:               event.ip,
      rule_score:       event.rule_score,
      anomaly_score:    event.anomaly_score,
      risk_score:       event.risk_score,
      risk_level:       event.risk_level,
      action:           event.action,
      strike_count:     event.strike_count,
      scoring_method:   event.scoring_method,
      reasons:          event.reasons,
      temporal_insight: event.temporal_insight,
      first_seen:       base.toISOString(),
      last_seen:        last.toISOString(),
    };
  }).sort((a, b) => b.risk_score - a.risk_score);
}

// ─── Async Fetchers (Real API) ────────────────────────────────────────────────

/**
 * Fetch system metrics from real API.
 */
export async function fetchSystemMetricsAsync(): Promise<SystemMetrics> {
  if (!USE_REAL_API) {
    return getSystemMetrics();
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/metrics`);
    if (!res.ok) throw new Error(`API ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API] Metrics fetch failed, using fallback:', err);
    return getSystemMetrics();
  }
}

/**
 * Fetch network nodes from real API.
 */
export async function fetchNetworkNodesAsync(): Promise<NetworkNode[]> {
  if (!USE_REAL_API) {
    return getNetworkNodes(16);
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/network-nodes`);
    if (!res.ok) throw new Error(`API ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API] Network nodes fetch failed, using fallback:', err);
    return getNetworkNodes(16);
  }
}

/**
 * Fetch hunting results from real API.
 */
export async function fetchHuntingResultsAsync(): Promise<HuntingResult[]> {
  if (!USE_REAL_API) {
    return getHuntingResults(15);
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/hunting-results`);
    if (!res.ok) throw new Error(`API ${res.status}`);
    const events = await res.json();
    return events.map((e: any) => {
      // Normalize the event first
      const normalized = normalizeSIEMEvent(e);
      return {
        ip: normalized.ip,
        rule_score: normalized.rule_score,
        anomaly_score: normalized.anomaly_score,
        risk_score: normalized.risk_score,
        risk_level: normalized.risk_level,
        action: normalized.action,
        strike_count: normalized.strike_count,
        scoring_method: normalized.scoring_method,
        reasons: normalized.reasons,
        temporal_insight: normalized.temporal_insight,
        first_seen: e.first_seen || normalized.timestamp,
        last_seen: e.last_seen || normalized.timestamp,
      };
    });
  } catch (err) {
    console.warn('[API] Hunting results fetch failed, using fallback:', err);
    return getHuntingResults(15);
  }
}

/** Build a live log entry string (for LogExplorer / Dashboard stream). */
export function formatLogLine(event: SIEMEvent): {
  time: string;
  level: LogSeverity;
  message: string;
} {
  const levelMap: Record<RiskLevel, LogSeverity> = {
    normal: 'INFO',
    low:    'INFO',
    medium: 'WARN',
    high:   'CRIT',
  };
  const actionMsg: Record<Action, string> = {
    monitor:    'Monitoring elevated activity',
    rate_limit: 'Rate-limiting applied',
    block:      'CONNECTION BLOCKED — threat isolated',
  };
  return {
    time:    timeLabel(),
    level:   levelMap[event.risk_level],
    message: `[${event.ip}] ${actionMsg[event.action]} | risk=${event.risk_score.toFixed(0)} rule=${event.rule_score} anomaly=${event.anomaly_score.toFixed(2)} | ${event.reasons[0]}`,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// WEBSOCKET STREAMING
// ═══════════════════════════════════════════════════════════════════════════════

export type StreamEventHandler = (events: SIEMEvent[]) => void;
export type StreamErrorHandler = (error: Error) => void;
export type StreamStatusHandler = (status: 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR') => void;

/**
 * WebSocket stream manager for real-time events.
 * 
 * Usage:
 *   const stream = createStreamManager();
 *   stream.onStatus(status => console.log(status));
 *   stream.onEvents(events => setEvents(events));
 *   stream.connect();
 *   // ... later
 *   stream.disconnect();
 */
export class SIEMStreamManager {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 3000;
  private eventHandlers: StreamEventHandler[] = [];
  private statusHandlers: StreamStatusHandler[] = [];
  private errorHandlers: StreamErrorHandler[] = [];
  private mockIntervalId: number | null = null;

  constructor(private useRealApi = USE_REAL_API) {}

  /**
   * Subscribe to stream events.
   */
  onEvents(handler: StreamEventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter(h => h !== handler);
    };
  }

  /**
   * Subscribe to connection status changes.
   */
  onStatus(handler: StreamStatusHandler): () => void {
    this.statusHandlers.push(handler);
    return () => {
      this.statusHandlers = this.statusHandlers.filter(h => h !== handler);
    };
  }

  /**
   * Subscribe to errors.
   */
  onError(handler: StreamErrorHandler): () => void {
    this.errorHandlers.push(handler);
    return () => {
      this.errorHandlers = this.errorHandlers.filter(h => h !== handler);
    };
  }

  /**
   * Connect to stream (real WebSocket or mock polling).
   */
  connect(): void {
    if (!this.useRealApi) {
      this.connectMock();
      return;
    }

    this.notifyStatus('CONNECTING');

    const wsUrl = `ws://127.0.0.1:8001/api/stream`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('[Stream] Connected to WebSocket');
      this.reconnectAttempts = 0;
      this.notifyStatus('CONNECTED');
    };

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.data && Array.isArray(message.data)) {
          // Normalize all events before notifying
          const normalized = message.data.map((e: any) => normalizeSIEMEvent(e));
          this.notifyEvents(normalized);
        }
      } catch (error) {
        console.error('[Stream] Failed to parse message:', error);
      }
    };

    this.ws.onerror = (error) => {
      console.error('[Stream] WebSocket error:', error);
      this.notifyError(new Error('WebSocket error'));
      this.notifyStatus('ERROR');
    };

    this.ws.onclose = () => {
      console.log('[Stream] WebSocket closed');
      this.notifyStatus('DISCONNECTED');
      this.attemptReconnect();
    };
  }

  /**
   * Mock streaming (polling-based for development/fallback).
   */
  private connectMock(): void {
    console.log('[Stream] Using mock streaming');
    this.notifyStatus('CONNECTED');

    this.mockIntervalId = window.setInterval(() => {
      const events = generateEventBatch(1);
      this.notifyEvents(events);
    }, 2000) as unknown as number;
  }

  /**
   * Attempt to reconnect with exponential backoff.
   */
  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.notifyError(new Error('Max reconnection attempts exceeded'));
      this.notifyStatus('ERROR');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);

    console.log(`[Stream] Reconnecting in ${Math.round(delay)}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => this.connect(), delay);
  }

  /**
   * Disconnect from stream.
   */
  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    if (this.mockIntervalId !== null) {
      clearInterval(this.mockIntervalId);
      this.mockIntervalId = null;
    }

    this.notifyStatus('DISCONNECTED');
  }

  /**
   * Check if connected.
   */
  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN || this.mockIntervalId !== null;
  }

  // ─── Notify Subscribers ────────────────────────────────────────────────────

  private notifyEvents(events: SIEMEvent[]): void {
    for (const handler of this.eventHandlers) {
      try {
        handler(events);
      } catch (error) {
        console.error('[Stream] Error in event handler:', error);
      }
    }
  }

  private notifyStatus(status: 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR'): void {
    for (const handler of this.statusHandlers) {
      try {
        handler(status);
      } catch (error) {
        console.error('[Stream] Error in status handler:', error);
      }
    }
  }

  private notifyError(error: Error): void {
    for (const handler of this.errorHandlers) {
      try {
        handler(error);
      } catch (e) {
        console.error('[Stream] Error in error handler:', e);
      }
    }
  }
}

/**
 * Create a new stream manager instance.
 */
export function createStreamManager(): SIEMStreamManager {
  return new SIEMStreamManager(USE_REAL_API);
}
