/**
 * Central frontend data layer.
 *
 * - USE_REAL_API = true: consume FastAPI backend and never silently switch to mock data.
 * - USE_REAL_API = false: use local mock generators for demo-only flows.
 */

export const USE_REAL_API = true;
export const API_BASE_URL = 'http://127.0.0.1:8001';

export type RiskLevel = 'normal' | 'low' | 'medium' | 'high';
export type Action = 'monitor' | 'rate_limit' | 'block' | 'escalate_manual_review';
export type ScoringMethod = 'linear' | 'adaptive' | 'boosted' | 'sigmoid';
export type LogSeverity = 'INFO' | 'WARN' | 'CRIT' | 'DEBUG';

export interface Alert {
  id: string;
  ip: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  state: 'TRIGGERED' | 'ACKNOWLEDGED' | 'RESOLVED';
  triggered_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  events_correlated: number;
  description: string;
  updated_at: string;
}

export interface ManualOverride {
  action: Action;
  reason: string;
  source: string;
  created_at: string;
}

export interface SIEMEvent {
  id: string;
  timestamp: string;
  ip: string;
  rule_score: number;
  anomaly_score: number;
  raw_anomaly_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  action: Action;
  reasons: string[];
  scoring_method: ScoringMethod;
  temporal_insight: string;
  failed_count: number;
  request_rate: number;
  username_variance: number;
  failed_ratio: number;
  event_count: number;
  total_attempts?: number;
  strike_count: number;
  repeat_incidents: number;
  adaptive_sensitivity: number;
  manual_override?: ManualOverride | null;
}

export interface SystemMetrics {
  status: 'NOMINAL' | 'ELEVATED' | 'CRITICAL';
  events_24h: string;
  events_trend: number;
  active_suspicious_ips: number;
  critical_nodes_isolated: number;
  high_risk_count: number;
  elevated_anomaly_count: number;
  baseline_count: number;
}

export interface TelemetryPoint {
  time: string;
  timestamp?: string;
  volume: number;
  risk: number;
  event_rate_per_sec?: number;
  active_ips?: number;
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

export interface HuntingResult extends SIEMEvent {
  first_seen: string;
  last_seen: string;
}

export interface TimelinePoint {
  id: string;
  timestamp: string;
  risk_score: number;
  rule_score: number;
  anomaly_score: number;
  action: Action;
  risk_level: RiskLevel;
  event_count: number;
  failed_count: number;
  request_rate: number;
  username_variance: number;
  failed_ratio: number;
}

export interface IpHistoryResponse {
  ip: string;
  history: SIEMEvent[];
  manual_override?: ManualOverride | null;
}

export interface IpTimelineResponse {
  ip: string;
  timeline: TimelinePoint[];
  manual_override?: ManualOverride | null;
}

export interface DebugStats {
  backend_started_at: string | null;
  model_loaded: boolean;
  records_loaded: number;
  parsed_events_loaded: number;
  unique_ips: number;
  active_connections: number;
  total_connections: number;
  total_disconnects: number;
  total_batches_sent: number;
  total_events_sent: number;
  broadcast_errors: number;
  stream_position: number;
  last_batch_at: string | null;
  event_rate_per_sec: number;
  latest_volume: number;
  latest_risk: number;
  decision_count: number;
  manual_overrides: Record<string, ManualOverride>;
}

export interface ReportSummary {
  id: string;
  date: string;
  label: string;
  status: string;
  incident_count: number;
  high_risk_count: number;
  medium_risk_count: number;
  baseline_count: number;
  unique_ip_count: number;
  generated_at: string;
}

export interface ReportDetail extends ReportSummary {
  unique_ips: string[];
  top_events: SIEMEvent[];
  manual_overrides: Record<string, ManualOverride>;
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

let seq = 0;
const uid = () => `evt-${Date.now()}-${++seq}`;
const rand = (min: number, max: number) => Math.random() * (max - min) + min;
const randI = (min: number, max: number) => Math.floor(rand(min, max));
const pick = <T>(arr: T[]): T => arr[randI(0, arr.length)];
const isoNow = () => new Date().toISOString();

const MOCK_IPS = [
  '203.0.113.45',
  '185.220.101.12',
  '45.33.32.156',
  '198.51.100.77',
  '91.108.4.200',
  '162.158.92.10',
  '104.21.16.35',
  '172.67.200.4',
];

const MOCK_REASONS: Record<RiskLevel, string[]> = {
  normal: ['No anomalies detected', 'Baseline traffic pattern'],
  low: ['Low rule score: 35', 'Minimal failed attempts detected'],
  medium: ['Medium rule score: 58', 'High request rate detected', 'Adaptive weighting applied'],
  high: ['High rule score: 87', 'Anomalous pattern detected: 0.872', 'BLOCKED: High risk status'],
};

function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 85) return 'high';
  if (score >= 65) return 'medium';
  if (score >= 40) return 'low';
  return 'normal';
}

function actionFromLevel(level: RiskLevel): Action {
  if (level === 'high') return 'block';
  if (level === 'medium') return 'rate_limit';
  return 'monitor';
}

function normalizeManualOverride(payload: any): ManualOverride | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const validActions: Action[] = ['monitor', 'rate_limit', 'block'];
  return {
    action: validActions.includes(payload.action) ? payload.action : 'monitor',
    reason: typeof payload.reason === 'string' ? payload.reason : 'Manual override',
    source: typeof payload.source === 'string' ? payload.source : 'unknown',
    created_at: typeof payload.created_at === 'string' ? payload.created_at : new Date().toISOString(),
  };
}

export function normalizeSIEMEvent(event: any): SIEMEvent {
  const risk_score = Math.max(0, Math.min(100, parseFloat(event?.risk_score) || 0));
  const anomaly_score = Math.max(0, Math.min(1, parseFloat(event?.anomaly_score) || 0));
  const raw_anomaly_score = Math.max(0, Math.min(1, parseFloat(event?.raw_anomaly_score) || anomaly_score));
  const rule_score = Math.max(0, Math.min(100, parseFloat(event?.rule_score) || 0));

  const validRiskLevels: RiskLevel[] = ['normal', 'low', 'medium', 'high'];
  const risk_level: RiskLevel = validRiskLevels.includes(event?.risk_level)
    ? event.risk_level
    : riskLevelFromScore(risk_score);

  const validActions: Action[] = ['monitor', 'rate_limit', 'block'];
  const action: Action = validActions.includes(event?.action)
    ? event.action
    : actionFromLevel(risk_level);

  const validMethods: ScoringMethod[] = ['linear', 'adaptive', 'boosted', 'sigmoid'];
  const scoring_method: ScoringMethod = validMethods.includes(event?.scoring_method)
    ? event.scoring_method
    : 'linear';

  return {
    id: typeof event?.id === 'string' ? event.id : uid(),
    timestamp: typeof event?.timestamp === 'string' ? event.timestamp : new Date().toISOString(),
    ip: typeof event?.ip === 'string' ? event.ip : '0.0.0.0',
    rule_score,
    anomaly_score,
    raw_anomaly_score,
    risk_score,
    risk_level,
    action,
    reasons: Array.isArray(event?.reasons) ? event.reasons.filter((item: unknown) => typeof item === 'string').slice(0, 10) : [],
    scoring_method,
    temporal_insight: typeof event?.temporal_insight === 'string' ? event.temporal_insight : '',
    failed_count: Math.max(0, Math.floor(event?.failed_count) || 0),
    request_rate: Math.max(0, parseFloat(event?.request_rate) || 0),
    username_variance: Math.max(0, Math.floor(event?.username_variance) || 0),
    failed_ratio: Math.max(0, Math.min(1, parseFloat(event?.failed_ratio) || 0)),
    event_count: Math.max(0, Math.floor(event?.event_count) || 0),
    total_attempts: event?.total_attempts === undefined ? undefined : Math.max(0, Math.floor(event.total_attempts) || 0),
    strike_count: Math.max(0, Math.floor(event?.strike_count) || 0),
    repeat_incidents: Math.max(0, Math.floor(event?.repeat_incidents) || 0),
    adaptive_sensitivity: Math.max(1, Math.min(3, parseFloat(event?.adaptive_sensitivity) || 1)),
    manual_override: normalizeManualOverride(event?.manual_override),
  };
}

export function generateSIEMEvent(overrides?: Partial<SIEMEvent>): SIEMEvent {
  const risk_score = parseFloat(rand(0, 100).toFixed(1));
  const risk_level = riskLevelFromScore(risk_score);
  const anomaly_score = parseFloat(rand(0, 1).toFixed(3));
  return {
    id: uid(),
    timestamp: isoNow(),
    ip: pick(MOCK_IPS),
    rule_score: randI(0, 100),
    anomaly_score,
    raw_anomaly_score: anomaly_score,
    risk_score,
    risk_level,
    action: actionFromLevel(risk_level),
    reasons: MOCK_REASONS[risk_level].slice(0, randI(1, MOCK_REASONS[risk_level].length + 1)),
    scoring_method: pick(['linear', 'adaptive', 'boosted', 'sigmoid'] as ScoringMethod[]),
    temporal_insight: risk_score > 70 ? 'High event concentration in single window' : '',
    failed_count: randI(0, 15),
    request_rate: parseFloat(rand(0, 0.2).toFixed(3)),
    username_variance: randI(1, 8),
    failed_ratio: parseFloat(rand(0, 1).toFixed(2)),
    event_count: randI(1, 12),
    total_attempts: randI(1, 30),
    strike_count: randI(0, 4),
    repeat_incidents: randI(0, 3),
    adaptive_sensitivity: parseFloat(rand(1, 2.5).toFixed(2)),
    manual_override: null,
    ...overrides,
  };
}

export function generateEventBatch(count = 20): SIEMEvent[] {
  return Array.from({ length: count }, () => generateSIEMEvent());
}

export function getSystemMetrics(): SystemMetrics {
  const high = randI(10, 40);
  const elevated = randI(25, 80);
  const baseline = randI(40, 150);
  const total = high + elevated + baseline;
  return {
    status: high / total > 0.15 ? 'CRITICAL' : elevated / total > 0.10 ? 'ELEVATED' : 'NOMINAL',
    events_24h: String(total),
    events_trend: parseFloat(rand(-5, 10).toFixed(1)),
    active_suspicious_ips: total,
    critical_nodes_isolated: high,
    high_risk_count: high,
    elevated_anomaly_count: elevated,
    baseline_count: baseline,
  };
}

export function getTelemetryHistory(hours = 12): TelemetryPoint[] {
  const now = new Date();
  return Array.from({ length: hours }, (_, index) => {
    const time = new Date(now.getTime() - (hours - 1 - index) * 3600_000);
    return {
      time: `${String(time.getHours()).padStart(2, '0')}:00`,
      timestamp: time.toISOString(),
      volume: randI(1, 15),
      risk: parseFloat(rand(0, 100).toFixed(2)),
      event_rate_per_sec: parseFloat(rand(0, 0.3).toFixed(3)),
      active_ips: randI(1, 8),
    };
  });
}

export function getNetworkNodes(count = 8): NetworkNode[] {
  return Array.from({ length: count }, (_, index) => {
    const risk_score = parseFloat(rand(0, 100).toFixed(1));
    const risk_level = riskLevelFromScore(risk_score);
    return {
      id: `node-${index}`,
      ip: pick(MOCK_IPS),
      risk_level,
      risk_score,
      action: actionFromLevel(risk_level),
      event_count: randI(1, 20),
      label: `Node-${String(index + 1).padStart(2, '0')}`,
      country: 'UNK',
    };
  });
}

export function getHuntingResults(count = 10): HuntingResult[] {
  return Array.from({ length: count }, () => {
    const event = generateSIEMEvent();
    return {
      ...event,
      first_seen: new Date(Date.now() - randI(3600_000, 36_000_000)).toISOString(),
      last_seen: event.timestamp,
    };
  }).sort((a, b) => b.risk_score - a.risk_score);
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, init);
  if (!response.ok) {
    throw new Error(`API ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function sanitizeTelemetryPoint(point: any): TelemetryPoint {
  return {
    time: typeof point?.time === 'string' ? point.time : '--:--',
    timestamp: typeof point?.timestamp === 'string' ? point.timestamp : undefined,
    volume: Math.max(0, Math.floor(point?.volume) || 0),
    risk: Math.max(0, Math.min(100, parseFloat(point?.risk) || 0)),
    event_rate_per_sec: Math.max(0, parseFloat(point?.event_rate_per_sec) || 0),
    active_ips: Math.max(0, Math.floor(point?.active_ips) || 0),
  };
}

function sanitizeNetworkNode(node: any): NetworkNode {
  const risk_score = Math.max(0, Math.min(100, parseFloat(node?.risk_score) || 0));
  const risk_level = ['normal', 'low', 'medium', 'high'].includes(node?.risk_level)
    ? node.risk_level as RiskLevel
    : riskLevelFromScore(risk_score);
  return {
    id: typeof node?.id === 'string' ? node.id : uid(),
    ip: typeof node?.ip === 'string' ? node.ip : '0.0.0.0',
    risk_level,
    risk_score,
    action: ['monitor', 'rate_limit', 'block'].includes(node?.action) ? node.action as Action : actionFromLevel(risk_level),
    event_count: Math.max(0, Math.floor(node?.event_count) || 0),
    label: typeof node?.label === 'string' ? node.label : undefined,
    country: typeof node?.country === 'string' ? node.country : undefined,
  };
}

function sanitizeHuntingResult(payload: any): HuntingResult {
  const normalized = normalizeSIEMEvent(payload);
  return {
    ...normalized,
    first_seen: typeof payload?.first_seen === 'string' ? payload.first_seen : normalized.timestamp,
    last_seen: typeof payload?.last_seen === 'string' ? payload.last_seen : normalized.timestamp,
  };
}

function sanitizeDebugStats(payload: any): DebugStats {
  return {
    backend_started_at: typeof payload?.backend_started_at === 'string' ? payload.backend_started_at : null,
    model_loaded: Boolean(payload?.model_loaded),
    records_loaded: Math.max(0, Math.floor(payload?.records_loaded) || 0),
    parsed_events_loaded: Math.max(0, Math.floor(payload?.parsed_events_loaded) || 0),
    unique_ips: Math.max(0, Math.floor(payload?.unique_ips) || 0),
    active_connections: Math.max(0, Math.floor(payload?.active_connections) || 0),
    total_connections: Math.max(0, Math.floor(payload?.total_connections) || 0),
    total_disconnects: Math.max(0, Math.floor(payload?.total_disconnects) || 0),
    total_batches_sent: Math.max(0, Math.floor(payload?.total_batches_sent) || 0),
    total_events_sent: Math.max(0, Math.floor(payload?.total_events_sent) || 0),
    broadcast_errors: Math.max(0, Math.floor(payload?.broadcast_errors) || 0),
    stream_position: Math.max(0, Math.floor(payload?.stream_position) || 0),
    last_batch_at: typeof payload?.last_batch_at === 'string' ? payload.last_batch_at : null,
    event_rate_per_sec: Math.max(0, parseFloat(payload?.event_rate_per_sec) || 0),
    latest_volume: Math.max(0, Math.floor(payload?.latest_volume) || 0),
    latest_risk: Math.max(0, Math.min(100, parseFloat(payload?.latest_risk) || 0)),
    decision_count: Math.max(0, Math.floor(payload?.decision_count) || 0),
    manual_overrides: Object.fromEntries(
      Object.entries(payload?.manual_overrides ?? {}).map(([ip, override]) => [ip, normalizeManualOverride(override)!]),
    ),
  };
}

export async function fetchSystemMetricsAsync(): Promise<SystemMetrics> {
  if (!USE_REAL_API) {
    return getSystemMetrics();
  }

  try {
    return await fetchJson<SystemMetrics>('/api/metrics');
  } catch (error) {
    console.warn('[API] Metrics fetch failed:', error);
    return EMPTY_METRICS;
  }
}

export async function fetchTelemetryAsync(): Promise<TelemetryPoint[]> {
  if (!USE_REAL_API) {
    return getTelemetryHistory(12);
  }

  try {
    const payload = await fetchJson<any[]>('/api/telemetry');
    return Array.isArray(payload) ? payload.map(sanitizeTelemetryPoint) : [];
  } catch (error) {
    console.warn('[API] Telemetry fetch failed:', error);
    return [];
  }
}

export async function fetchDebugStatsAsync(): Promise<DebugStats> {
  if (!USE_REAL_API) {
    return EMPTY_DEBUG;
  }

  try {
    const payload = await fetchJson<any>('/api/debug');
    return sanitizeDebugStats(payload);
  } catch (error) {
    console.warn('[API] Debug fetch failed:', error);
    return EMPTY_DEBUG;
  }
}

export async function fetchNetworkNodesAsync(): Promise<NetworkNode[]> {
  if (!USE_REAL_API) {
    return getNetworkNodes();
  }

  try {
    const payload = await fetchJson<any[]>('/api/network-nodes');
    return Array.isArray(payload) ? payload.map(sanitizeNetworkNode) : [];
  } catch (error) {
    console.warn('[API] Network node fetch failed:', error);
    return [];
  }
}

export async function fetchHuntingResultsAsync(): Promise<HuntingResult[]> {
  if (!USE_REAL_API) {
    return getHuntingResults(15);
  }

  try {
    const payload = await fetchJson<any[]>('/api/hunting-results');
    return Array.isArray(payload) ? payload.map(sanitizeHuntingResult) : [];
  } catch (error) {
    console.warn('[API] Hunting results fetch failed:', error);
    return [];
  }
}

export async function blockIpAsync(ip: string, reason = 'Blocked from dashboard'): Promise<void> {
  await fetchJson('/api/actions/block-ip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason, source: 'frontend' }),
  });
}

export async function enforcePolicyAsync(ip: string, action: Action, reason = 'Policy enforced from dashboard'): Promise<void> {
  await fetchJson('/api/actions/enforce-policy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, action, reason, source: 'frontend' }),
  });
}

export async function fetchIpHistoryAsync(ip: string): Promise<IpHistoryResponse> {
  const payload = await fetchJson<any>(`/api/ip/${encodeURIComponent(ip)}/history`);
  return {
    ip,
    history: Array.isArray(payload?.history) ? payload.history.map(normalizeSIEMEvent) : [],
    manual_override: normalizeManualOverride(payload?.manual_override),
  };
}

export async function fetchIpTimelineAsync(ip: string): Promise<IpTimelineResponse> {
  const payload = await fetchJson<any>(`/api/ip/${encodeURIComponent(ip)}/timeline`);
  return {
    ip,
    timeline: Array.isArray(payload?.timeline)
      ? payload.timeline.map((point: any) => ({
          id: typeof point?.id === 'string' ? point.id : uid(),
          timestamp: typeof point?.timestamp === 'string' ? point.timestamp : new Date().toISOString(),
          risk_score: Math.max(0, Math.min(100, parseFloat(point?.risk_score) || 0)),
          rule_score: Math.max(0, Math.min(100, parseFloat(point?.rule_score) || 0)),
          anomaly_score: Math.max(0, Math.min(1, parseFloat(point?.anomaly_score) || 0)),
          action: ['monitor', 'rate_limit', 'block'].includes(point?.action) ? point.action as Action : 'monitor',
          risk_level: ['normal', 'low', 'medium', 'high'].includes(point?.risk_level) ? point.risk_level as RiskLevel : 'normal',
          event_count: Math.max(0, Math.floor(point?.event_count) || 0),
          failed_count: Math.max(0, Math.floor(point?.failed_count) || 0),
          request_rate: Math.max(0, parseFloat(point?.request_rate) || 0),
          username_variance: Math.max(0, Math.floor(point?.username_variance) || 0),
          failed_ratio: Math.max(0, Math.min(1, parseFloat(point?.failed_ratio) || 0)),
        }))
      : [],
    manual_override: normalizeManualOverride(payload?.manual_override),
  };
}

export async function fetchReportsAsync(): Promise<ReportSummary[]> {
  const payload = await fetchJson<any[]>('/api/reports');
  return Array.isArray(payload)
    ? payload.map((report) => ({
        id: typeof report?.id === 'string' ? report.id : uid(),
        date: typeof report?.date === 'string' ? report.date : '',
        label: typeof report?.label === 'string' ? report.label : (typeof report?.date === 'string' ? report.date : 'Unknown'),
        status: typeof report?.status === 'string' ? report.status : 'Ready',
        incident_count: Math.max(0, Math.floor(report?.incident_count) || 0),
        high_risk_count: Math.max(0, Math.floor(report?.high_risk_count) || 0),
        medium_risk_count: Math.max(0, Math.floor(report?.medium_risk_count) || 0),
        baseline_count: Math.max(0, Math.floor(report?.baseline_count) || 0),
        unique_ip_count: Math.max(0, Math.floor(report?.unique_ip_count) || 0),
        generated_at: typeof report?.generated_at === 'string' ? report.generated_at : new Date().toISOString(),
      }))
    : [];
}

export async function fetchReportDetailAsync(reportId: string): Promise<ReportDetail> {
  const payload = await fetchJson<any>(`/api/reports/${encodeURIComponent(reportId)}.json`);
  return {
    id: payload?.id ?? reportId,
    date: payload?.date ?? '',
    label: payload?.label ?? payload?.date ?? reportId,
    status: payload?.status ?? 'Ready',
    incident_count: Math.max(0, Math.floor(payload?.incident_count) || 0),
    high_risk_count: Math.max(0, Math.floor(payload?.high_risk_count) || 0),
    medium_risk_count: Math.max(0, Math.floor(payload?.medium_risk_count) || 0),
    baseline_count: Math.max(0, Math.floor(payload?.baseline_count) || 0),
    unique_ip_count: Math.max(0, Math.floor(payload?.unique_ip_count) || 0),
    generated_at: typeof payload?.generated_at === 'string' ? payload.generated_at : new Date().toISOString(),
    unique_ips: Array.isArray(payload?.unique_ips) ? payload.unique_ips.filter((item: unknown) => typeof item === 'string') : [],
    top_events: Array.isArray(payload?.top_events) ? payload.top_events.map(normalizeSIEMEvent) : [],
    manual_overrides: Object.fromEntries(
      Object.entries(payload?.manual_overrides ?? {}).map(([ip, override]) => [ip, normalizeManualOverride(override)!]),
    ),
  };
}

async function downloadBlob(path: string, filename: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw new Error(`API ${response.status}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function downloadReportJsonAsync(reportId: string): Promise<void> {
  await downloadBlob(`/api/reports/${encodeURIComponent(reportId)}.json`, `${reportId}.json`);
}

export async function downloadReportPdfAsync(reportId: string): Promise<void> {
  await downloadBlob(`/api/reports/${encodeURIComponent(reportId)}.pdf`, `${reportId}.pdf`);
}

export function formatLogLine(event: SIEMEvent): { time: string; level: LogSeverity; message: string } {
  const levelMap: Record<RiskLevel, LogSeverity> = {
    normal: 'INFO',
    low: 'INFO',
    medium: 'WARN',
    high: 'CRIT',
  };
  const actionMsg: Record<Action, string> = {
    monitor: 'Monitoring elevated activity',
    rate_limit: 'Rate-limiting applied',
    block: 'Connection blocked',
  };
  const eventTime = new Date(event.timestamp);
  const time = Number.isNaN(eventTime.getTime())
    ? '--:--:--'
    : eventTime.toLocaleTimeString('id-ID', { hour12: false });

  return {
    time,
    level: levelMap[event.risk_level],
    message: `[${event.ip}] ${actionMsg[event.action]} | risk=${event.risk_score.toFixed(0)} rule=${event.rule_score} anomaly=${event.anomaly_score.toFixed(2)} | ${event.reasons[0] ?? 'No reasons'}`,
  };
}

export type StreamEventHandler = (events: SIEMEvent[]) => void;
export type StreamErrorHandler = (error: Error) => void;
export type StreamStatusHandler = (status: 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR') => void;

export class SIEMStreamManager {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts = 5;
  private readonly reconnectDelay = 3000;
  private reconnectTimer: number | null = null;
  private shouldReconnect = true;
  private eventHandlers: StreamEventHandler[] = [];
  private statusHandlers: StreamStatusHandler[] = [];
  private errorHandlers: StreamErrorHandler[] = [];
  private mockIntervalId: number | null = null;

  constructor(private readonly useRealApi = USE_REAL_API) {}

  onEvents(handler: StreamEventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter((item) => item !== handler);
    };
  }

  onStatus(handler: StreamStatusHandler): () => void {
    this.statusHandlers.push(handler);
    return () => {
      this.statusHandlers = this.statusHandlers.filter((item) => item !== handler);
    };
  }

  onError(handler: StreamErrorHandler): () => void {
    this.errorHandlers.push(handler);
    return () => {
      this.errorHandlers = this.errorHandlers.filter((item) => item !== handler);
    };
  }

  connect(): void {
    this.shouldReconnect = true;

    if (!this.useRealApi) {
      this.connectMock();
      return;
    }

    this.notifyStatus('CONNECTING');
    this.ws = new WebSocket(`${API_BASE_URL.replace(/^http/, 'ws')}/api/stream`);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.notifyStatus('CONNECTED');
    };

    this.ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload?.data && Array.isArray(payload.data)) {
          this.notifyEvents(payload.data.map(normalizeSIEMEvent));
        }
      } catch (error) {
        this.notifyError(new Error('Failed to parse WebSocket payload'));
        console.error('[Stream] Failed to parse message:', error);
      }
    };

    this.ws.onerror = () => {
      this.notifyError(new Error('WebSocket error'));
      this.notifyStatus('ERROR');
    };

    this.ws.onclose = () => {
      this.notifyStatus('DISCONNECTED');
      if (this.shouldReconnect) {
        this.attemptReconnect();
      }
    };
  }

  private connectMock(): void {
    this.notifyStatus('CONNECTED');
    this.mockIntervalId = window.setInterval(() => {
      this.notifyEvents(generateEventBatch(1));
    }, 2000) as unknown as number;
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.notifyError(new Error('Max reconnection attempts exceeded'));
      this.notifyStatus('ERROR');
      return;
    }

    this.reconnectAttempts += 1;
    const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
    }
    this.reconnectTimer = window.setTimeout(() => this.connect(), delay);
  }

  disconnect(): void {
    this.shouldReconnect = false;

    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

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

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN || this.mockIntervalId !== null;
  }

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
      } catch (handlerError) {
        console.error('[Stream] Error in error handler:', handlerError);
      }
    }
  }
}

export function createStreamManager(): SIEMStreamManager {
  return new SIEMStreamManager(USE_REAL_API);
}

export async function fetchAllAlertsAsync(limit: number = 100): Promise<Alert[]> {
  try {
    const payload = await fetchJson<any[]>(`/api/alerts/all?limit=${limit}`);
    return Array.isArray(payload) ? payload : [];
  } catch (error) {
    console.warn('[API] Fetch alerts failed:', error);
    return [];
  }
}

export async function acknowledgeAlertAsync(alertId: string): Promise<Alert | null> {
  try {
    const payload = await fetchJson<Alert>('/api/alerts/acknowledge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId }),
    });
    return payload;
  } catch (error) {
    console.warn('[API] Acknowledge alert failed:', error);
    return null;
  }
}

export async function resolveAlertAsync(alertId: string): Promise<Alert | null> {
  try {
    const payload = await fetchJson<Alert>('/api/alerts/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId }),
    });
    return payload;
  } catch (error) {
    console.warn('[API] Resolve alert failed:', error);
    return null;
  }
}
