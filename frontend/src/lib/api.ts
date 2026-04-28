/**
 * src/lib/api.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Hybrid SIEM — Central Data Layer (Mock Service)
 *
 * Rules:
 *  - ALL data originates here. Components MUST NOT generate their own data.
 *  - Mirrors the backend PipelineDecision contract from hybrid_siem/pipeline.py
 *  - Ready to swap: replace generators with real fetch() calls when API is live.
 * ──────────────────────────────────────────────────────────────────────────────
 */

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
