'use client';

import React, { useState } from 'react';
import { Shield, AlertTriangle, Search, Activity, CheckCircle, Crosshair } from 'lucide-react';

interface IntelReport {
  status: 'success' | 'error';
  type: string;
  target: string;
  risk_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: string[];
  details: Record<string, any>;
  timestamp?: string;
}

export function IntelEnrichmentPanel() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<IntelReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/osint/enrich?target=${encodeURIComponent(query.trim())}`);
      const data = await res.json();

      if (data.status === 'success') {
        setReport(data);
      } else {
        setError(data.message || 'Error fetching OSINT report');
        setReport(null);
      }
    } catch (err: any) {
      setError(err.message || 'Network error');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const getThreatBadgeColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  return (
    <div className="w-full max-w-md bg-slate-950/90 border border-cyan-500/30 rounded-xl p-4 shadow-2xl backdrop-blur-md text-slate-100 font-sans">
      <div className="flex items-center gap-2 mb-4 border-b border-cyan-500/20 pb-3">
        <Crosshair className="w-5 h-5 text-cyan-400 animate-pulse" />
        <h2 className="text-lg font-bold tracking-wider text-cyan-300 uppercase">OSINT Intel & Threat Analysis</h2>
      </div>

      <form onSubmit={handleSearch} className="flex gap-2 mb-4">
        <div className="relative flex-1">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Enter IP, MMSI or Callsign (e.g. FORTE11, 10.0.0.1)"
            className="w-full bg-slate-900/80 border border-slate-700 focus:border-cyan-400 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none transition"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-1 transition shadow-lg shadow-cyan-600/20"
        >
          {loading ? <Activity className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          Scan
        </button>
      </form>

      {error && (
        <div className="bg-red-950/40 border border-red-500/30 text-red-300 text-xs p-3 rounded-lg flex items-center gap-2 mb-4">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {report && (
        <div className="space-y-3 bg-slate-900/50 p-3 rounded-lg border border-slate-800">
          <div className="flex justify-between items-center">
            <span className="text-xs text-slate-400 uppercase tracking-widest">Target: {report.target}</span>
            <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${getThreatBadgeColor(report.threat_level)}`}>
              {report.threat_level} ({report.risk_score}/100)
            </span>
          </div>

          <div className="space-y-1">
            <div className="text-xs text-slate-400 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Type: <strong className="text-cyan-300 capitalize">{report.type}</strong></span>
            </div>
          </div>

          <div>
            <span className="text-xs font-semibold text-slate-300 block mb-1">Threat Indicators:</span>
            {report.indicators.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {report.indicators.map((ind, i) => (
                  <span key={i} className="bg-red-900/30 border border-red-700/50 text-red-300 text-[11px] px-2 py-0.5 rounded">
                    {ind}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-xs text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>No high-severity threats detected.</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
