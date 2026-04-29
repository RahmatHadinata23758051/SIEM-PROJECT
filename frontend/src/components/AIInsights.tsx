import React, { useEffect, useMemo, useState } from 'react';
import { Activity, BrainCircuit, Crosshair, PieChart as PieChartIcon, ShieldCheck } from 'lucide-react';
import { Cell, Legend, Pie, PieChart, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip } from 'recharts';
import { fetchHuntingResultsAsync, type HuntingResult } from '../lib/api';
import { useSIEMStream } from '../hooks/useSIEMStream';

export default function AIInsights() {
  const { events, debug } = useSIEMStream();
  const [fallbackResults, setFallbackResults] = useState<HuntingResult[]>([]);

  useEffect(() => {
    if (events.length > 0) return;
    let cancelled = false;
    fetchHuntingResultsAsync()
      .then((results) => {
        if (!cancelled) {
          setFallbackResults(results);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFallbackResults([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [events.length]);

  const results = useMemo<HuntingResult[]>(() => {
    if (events.length > 0) {
      return events.map((event) => ({
        ...event,
        first_seen: event.timestamp,
        last_seen: event.timestamp,
      }));
    }
    return fallbackResults;
  }, [events, fallbackResults]);

  const total = results.length;
  const methodStats = useMemo(() => {
    const counts = results.reduce((accumulator, result) => {
      accumulator[result.scoring_method] = (accumulator[result.scoring_method] || 0) + 1;
      return accumulator;
    }, {} as Record<string, number>);
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [results]);

  const radarData = useMemo(
    () =>
      results.slice(0, 5).map((result) => ({
        ip: result.ip,
        rule: result.rule_score,
        anomaly: result.anomaly_score * 100,
        risk: result.risk_score,
      })),
    [results],
  );

  const COLORS = ['#adc6ff', '#5c8aff', '#ffb4ab', '#10b981'];
  const avgAnomaly = total ? Math.round((results.reduce((sum, result) => sum + result.anomaly_score, 0) / total) * 100) : 0;

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">AI Decision Insights</h1>
          <p className="text-sm text-on-surface-variant mt-1">Aggregated scoring analytics from the live hybrid detection pipeline.</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <InsightCard icon={<BrainCircuit />} title="Tracked Decisions" value={String(total)} tone="primary" />
        <InsightCard icon={<Activity />} title="Avg Anomaly Confidence" value={`${avgAnomaly}%`} tone="tertiary" />
        <InsightCard icon={<Crosshair />} title="High Risk Detections" value={String(results.filter((result) => result.risk_level === 'high').length)} tone="error" />
        <InsightCard icon={<ShieldCheck />} title="Model Loaded" value={debug.model_loaded ? 'YES' : 'NO'} tone={debug.model_loaded ? 'primary' : 'error'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-[400px]">
        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col">
          <h3 className="font-semibold text-on-surface mb-4 flex items-center gap-2">
            <PieChartIcon className="text-primary" size={18} />
            Scoring Method Distribution
          </h3>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={methodStats} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                  {methodStats.map((entry, index) => (
                    <Cell key={`cell-${entry.name}-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col">
          <h3 className="font-semibold text-on-surface mb-4 flex items-center gap-2">
            <ShieldCheck className="text-tertiary" size={18} />
            Top Threats Profile (Rule vs Anomaly)
          </h3>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                <PolarGrid stroke="#424754" />
                <PolarAngleAxis dataKey="ip" tick={{ fill: '#8c909f', fontSize: 10 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#8c909f' }} />
                <Radar name="Rule Score" dataKey="rule" stroke="#adc6ff" fill="#adc6ff" fillOpacity={0.4} />
                <Radar name="Anomaly Score (x100)" dataKey="anomaly" stroke="#ffb4ab" fill="#ffb4ab" fillOpacity={0.4} />
                <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }} />
                <Legend />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

function InsightCard({ icon, title, value, tone }: { icon: React.ReactNode; title: string; value: string; tone: 'primary' | 'tertiary' | 'error' }) {
  const toneClass = tone === 'primary' ? 'text-primary' : tone === 'tertiary' ? 'text-tertiary' : 'text-error';
  return (
    <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6">
      <div className={`flex items-center gap-3 ${toneClass} mb-2`}>
        {icon}
        <h3 className="font-bold">{title}</h3>
      </div>
      <p className="text-4xl font-black text-on-surface">{value}</p>
    </div>
  );
}
