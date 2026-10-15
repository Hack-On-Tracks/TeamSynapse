import React, { useState, useEffect } from 'react';
import { ShieldAlert, CheckCircle2, AlertOctagon, HelpCircle, RefreshCw, Filter, FileText } from 'lucide-react';

interface ThreatCase {
  case_id: string;
  entity_id: string;
  priority_rank: number;
  case_score: number;
  severity: string;
  confidence: number;
  status: string;
  title: string;
  description: string;
  evidence_summary: string;
  created_at: string;
}

export const ThreatCasesView: React.FC = () => {
  const [cases, setCases] = useState<ThreatCase[]>([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/score/cases?limit=100');
      if (res.ok) {
        const data = await res.json();
        setCases(Array.isArray(data) ? data : []);
      }
    } catch (e) {
      console.error('Failed to fetch cases:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleUpdateStatus = async (caseId: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/score/case/${caseId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        setCases((prev) =>
          prev.map((c) => (c.case_id === caseId ? { ...c, status: newStatus } : c))
        );
      }
    } catch (e) {
      console.error('Failed to update status:', e);
    }
  };

  const filtered = cases.filter((c) => statusFilter === 'ALL' || c.status === statusFilter);

  return (
    <div style={{ padding: 24, height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldAlert style={{ color: 'var(--accent-cyan)' }} /> Threat Case Management & Analyst Triage
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
            Evidence-grounded case bundles with MITRE ATT&CK rationale, confidence indexing, and audit tracking.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ height: 34, fontSize: '0.82rem' }}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="MITIGATED">MITIGATED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
          <button
            onClick={fetchCases}
            style={{
              background: 'var(--bg-card)',
              color: 'var(--accent-cyan)',
              border: '1px solid var(--border-color)',
              padding: '6px 14px',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: '0.82rem',
              fontWeight: 600,
            }}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Cases List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {filtered.length === 0 ? (
          <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            No threat cases matching filter. Ingest telemetry or run cross-table scoring to generate cases.
          </div>
        ) : (
          filtered.map((c) => (
            <div
              key={c.case_id}
              className="glass-panel"
              style={{
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
                borderLeft: `4px solid ${
                  c.severity === 'CRITICAL' ? 'var(--accent-rose)' : c.severity === 'HIGH' ? 'var(--accent-amber)' : 'var(--accent-cyan)'
                }`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--accent-cyan)' }}>
                      #{c.priority_rank} — {c.case_id}
                    </span>
                    <span className={`badge badge-${c.severity.toLowerCase()}`}>{c.severity}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Entity: {c.entity_id}
                    </span>
                  </div>
                  <h4 style={{ fontWeight: 700, fontSize: '0.95rem', marginTop: 4 }}>{c.title}</h4>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>Status:</span>
                  <span
                    className="badge"
                    style={{
                      background: c.status === 'MITIGATED' ? 'rgba(16,185,129,0.2)' : 'rgba(56,189,248,0.2)',
                      color: c.status === 'MITIGATED' ? '#10b981' : '#38bdf8',
                      border: `1px solid ${c.status === 'MITIGATED' ? '#10b981' : '#38bdf8'}`,
                    }}
                  >
                    {c.status}
                  </span>
                </div>
              </div>

              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {c.description}
              </p>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, fontSize: '0.78rem', background: 'var(--bg-card)', padding: '8px 14px', borderRadius: 6 }}>
                <span><strong>Composite Risk:</strong> {c.case_score}/100</span>
                <span><strong>Confidence:</strong> {Math.round((c.confidence || 0.8) * 100)}%</span>
                <span><strong>Evidence Signals:</strong> <code style={{ color: 'var(--accent-cyan)' }}>{c.evidence_summary}</code></span>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
                <button
                  onClick={() => handleUpdateStatus(c.case_id, 'INVESTIGATING')}
                  style={{ background: 'var(--bg-card)', color: '#38bdf8', border: '1px solid var(--border-color)', padding: '5px 10px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600 }}
                >
                  Start Triage
                </button>
                <button
                  onClick={() => handleUpdateStatus(c.case_id, 'MITIGATED')}
                  style={{ background: 'var(--bg-card)', color: '#10b981', border: '1px solid var(--border-color)', padding: '5px 10px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600 }}
                >
                  Mitigate
                </button>
                <button
                  onClick={() => handleUpdateStatus(c.case_id, 'FALSE_POSITIVE')}
                  style={{ background: 'var(--bg-card)', color: '#ef4444', border: '1px solid var(--border-color)', padding: '5px 10px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600 }}
                >
                  False Positive
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
