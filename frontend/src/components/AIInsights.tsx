import React, { useMemo } from 'react';
import { getHuntingResults } from '../lib/api';
import { BrainCircuit, Activity, Crosshair, ShieldCheck, PieChart as PieChartIcon } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Legend } from 'recharts';

export default function AIInsights() {
  const results = useMemo(() => getHuntingResults(15), []);

  const total = results.length;
  const methodStats = useMemo(() => {
    const counts = results.reduce((acc, r) => {
      acc[r.scoring_method] = (acc[r.scoring_method] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [results]);

  const COLORS = ['#adc6ff', '#5c8aff', '#ffb4ab', '#10b981'];

  const radarData = useMemo(() => {
    return results.slice(0, 5).map(r => ({
      ip: r.ip,
      rule: r.rule_score,
      anomaly: r.anomaly_score * 100,
      risk: r.risk_score,
    }));
  }, [results]);

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">AI Decision Insights</h1>
          <p className="text-sm text-on-surface-variant mt-1">Aggregated scoring analytics from the Machine Learning pipeline.</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6">
          <div className="flex items-center gap-3 text-primary mb-2">
            <BrainCircuit />
            <h3 className="font-bold">Total Models Evaluated</h3>
          </div>
          <p className="text-4xl font-black text-on-surface">{total}</p>
        </div>
        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6">
          <div className="flex items-center gap-3 text-tertiary mb-2">
            <Activity />
            <h3 className="font-bold">Avg Anomaly Confidence</h3>
          </div>
          <p className="text-4xl font-black text-on-surface">
            {Math.round(results.reduce((a, b) => a + b.anomaly_score, 0) / total * 100)}%
          </p>
        </div>
        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6">
          <div className="flex items-center gap-3 text-error mb-2">
            <Crosshair />
            <h3 className="font-bold">High Risk Detections</h3>
          </div>
          <p className="text-4xl font-black text-on-surface">
            {results.filter(r => r.risk_level === 'high').length}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-[400px]">
        {/* Pie Chart: Scoring Methods */}
        <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col">
          <h3 className="font-semibold text-on-surface mb-4 flex items-center gap-2">
            <PieChartIcon className="text-primary" size={18} />
            Scoring Method Distribution
          </h3>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={methodStats}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {methodStats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1d2027', borderColor: '#424754', borderRadius: '8px' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Radar Chart: Top 5 Threats */}
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
