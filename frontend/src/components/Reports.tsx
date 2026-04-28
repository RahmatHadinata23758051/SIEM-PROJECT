import React, { useMemo } from 'react';
import { getHuntingResults } from '../lib/api';
import { FileText, Download, FileJson } from 'lucide-react';
import { cn } from '../lib/utils';

export default function Reports() {
  const reports = useMemo(() => {
    const today = new Date();
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(today.getTime() - i * 86400000);
      return {
        id: `REP-${d.getTime()}`,
        date: d.toLocaleDateString('id-ID', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }),
        incidents: Math.floor(Math.random() * 150 + 20),
        status: i === 0 ? 'Generating' : 'Ready',
      };
    });
  }, []);

  const handleExportJson = (dateLabel: string) => {
    const results = getHuntingResults(Math.floor(Math.random() * 50 + 10));
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-report-${dateLabel.replace(/\s+/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Compliance & Reports</h1>
          <p className="text-sm text-on-surface-variant mt-1">Export daily incident summaries and threat intelligence reports.</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {reports.map((report) => (
          <div key={report.id} className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col gap-4 hover:border-outline-variant/60 transition-colors group">
            <div className="flex justify-between items-start">
              <div className="p-3 bg-surface-container-high rounded-lg text-primary group-hover:scale-110 transition-transform">
                <FileText />
              </div>
              <span className={cn(
                'px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest border',
                report.status === 'Ready' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-tertiary/10 text-tertiary border-tertiary/20'
              )}>
                {report.status}
              </span>
            </div>
            
            <div>
              <h3 className="text-lg font-bold text-on-surface">{report.date}</h3>
              <p className="text-sm text-on-surface-variant mt-1">{report.incidents} High-Risk Incidents</p>
            </div>

            <div className="flex gap-2 mt-auto pt-4 border-t border-outline-variant/20">
              <button 
                disabled={report.status !== 'Ready'}
                className="flex-1 flex justify-center items-center gap-2 py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-surface-container-highest transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Download size={14} /> PDF
              </button>
              <button 
                disabled={report.status !== 'Ready'}
                onClick={() => handleExportJson(report.date)}
                className="flex-1 flex justify-center items-center gap-2 py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-surface-container-highest transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <FileJson size={14} /> JSON
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
