import React, { useEffect, useState } from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import { cn } from '../lib/utils';
import { downloadReportJsonAsync, downloadReportPdfAsync, fetchReportsAsync, type ReportSummary } from '../lib/api';

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchReportsAsync()
      .then((items) => {
        if (!cancelled) {
          setReports(items);
        }
      })
      .catch((fetchError: Error) => {
        if (!cancelled) {
          setError(fetchError.message || 'Failed to load reports');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="p-6 flex flex-col gap-6 h-full overflow-y-auto">
      <header className="flex justify-between items-end pb-4 border-b border-outline-variant/30">
        <div>
          <h1 className="text-2xl font-bold text-on-surface">Compliance &amp; Reports</h1>
          <p className="text-sm text-on-surface-variant mt-1">Export backend-generated daily incident summaries and threat intelligence reports.</p>
        </div>
      </header>

      {loading && <div className="text-sm text-on-surface-variant">Loading reports...</div>}
      {error && <div className="text-sm text-error">{error}</div>}
      {!loading && !error && reports.length === 0 && <div className="text-sm text-on-surface-variant">No reports available from backend.</div>}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {reports.map((report) => (
          <div key={report.id} className="bg-surface-container border border-outline-variant/30 rounded-xl p-6 flex flex-col gap-4 hover:border-outline-variant/60 transition-colors group">
            <div className="flex justify-between items-start">
              <div className="p-3 bg-surface-container-high rounded-lg text-primary group-hover:scale-110 transition-transform">
                <FileText />
              </div>
              <span
                className={cn(
                  'px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest border',
                  report.status === 'Ready' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-tertiary/10 text-tertiary border-tertiary/20',
                )}
              >
                {report.status}
              </span>
            </div>

            <div>
              <h3 className="text-lg font-bold text-on-surface">{report.label}</h3>
              <p className="text-sm text-on-surface-variant mt-1">
                {report.incident_count} medium/high incidents · {report.unique_ip_count} unique IPs
              </p>
            </div>

            <div className="grid grid-cols-3 gap-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
              <div className="bg-surface-container-low rounded-lg p-2 border border-outline-variant/20">High: {report.high_risk_count}</div>
              <div className="bg-surface-container-low rounded-lg p-2 border border-outline-variant/20">Medium: {report.medium_risk_count}</div>
              <div className="bg-surface-container-low rounded-lg p-2 border border-outline-variant/20">Base: {report.baseline_count}</div>
            </div>

            <div className="flex gap-2 mt-auto pt-4 border-t border-outline-variant/20">
              <button
                disabled={report.status !== 'Ready'}
                onClick={() => void downloadReportPdfAsync(report.id)}
                className="flex-1 flex justify-center items-center gap-2 py-2 bg-surface-container-high border border-outline-variant/30 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-surface-container-highest transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Download size={14} /> PDF
              </button>
              <button
                disabled={report.status !== 'Ready'}
                onClick={() => void downloadReportJsonAsync(report.id)}
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
