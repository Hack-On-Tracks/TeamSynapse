import React, { useState } from 'react';
import { X, ShieldAlert, ArrowUpRight, ArrowDownLeft, Clock, Activity, FileText, CheckCircle2, AlertTriangle } from 'lucide-react';

interface InvestigationDrawerProps {
  selectedNode: any | null;
  selectedEdge: any | null;
  onClose: () => void;
  onUpdateCaseStatus?: (caseId: string, status: string) => void;
}

export const InvestigationDrawer: React.FC<InvestigationDrawerProps> = ({
  selectedNode,
  selectedEdge,
  onClose,
  onUpdateCaseStatus,
}) => {
  if (!selectedNode && !selectedEdge) return null;

  return (
    <div
      style={{
        width: 380,
        height: '100%',
        background: 'var(--bg-surface)',
        borderLeft: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 30,
        boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'var(--bg-secondary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldAlert size={18} style={{ color: 'var(--accent-cyan)' }} />
          <span style={{ fontWeight: 700, fontSize: '0.95rem', letterSpacing: '0.02em' }}>
            {selectedNode ? 'Entity Investigation Dossier' : 'Aggregated Edge Evidence'}
          </span>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'transparent', color: 'var(--text-muted)', padding: 4, borderRadius: 4 }}
        >
          <X size={18} />
        </button>
      </div>

      {/* Body Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 18 }}>
        {selectedNode && (
          <>
            {/* Entity Overview Card */}
            <div style={{ background: 'var(--bg-card)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Pseudonymous Entity ID</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 2 }}>
                    {selectedNode.entity_id || selectedNode.id}
                  </div>
                </div>
                <span className={`badge badge-${(selectedNode.severity || 'low').toLowerCase()}`}>
                  {selectedNode.severity || 'LOW'} ({selectedNode.risk_score || 10})
                </span>
              </div>

              <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Node Type:</span>
                  <div style={{ fontWeight: 600 }}>{selectedNode.type}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>IP Address:</span>
                  <div style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{selectedNode.ip || selectedNode.id}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Asset Criticality:</span>
                  <div style={{ fontWeight: 600 }}>Tier {selectedNode.asset_tier || (selectedNode.id.startsWith('10.') ? 2 : 1)}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Graph Degree:</span>
                  <div style={{ fontWeight: 600 }}>{selectedNode.degree || 1} connections</div>
                </div>
              </div>
            </div>

            {/* Behavioral Baseline Deviations */}
            <div style={{ background: 'var(--bg-card)', padding: 14, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} /> Behavioral Baseline Comparison
              </div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
                {selectedNode.risk_score >= 60
                  ? `Outbound volume is ${(selectedNode.risk_score / 15).toFixed(1)}x higher than peer group median (Finance/Engineering). Temporal deviation flagged during off-hours.`
                  : 'Behavior aligns with historical 14-day rolling peer-group baseline. Normal protocol and port distribution.'}
              </p>
            </div>

            {/* Total Traffic Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div style={{ background: 'var(--bg-card)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  <ArrowUpRight size={14} style={{ color: 'var(--accent-rose)' }} /> Total Outbound
                </div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, marginTop: 4 }}>
                  {((selectedNode.total_volume || 0) / 1_000_000).toFixed(2)} MB
                </div>
              </div>
              <div style={{ background: 'var(--bg-card)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  <Clock size={14} style={{ color: 'var(--accent-cyan)' }} /> Observation
                </div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, marginTop: 4 }}>14 Days</div>
              </div>
            </div>
          </>
        )}

        {selectedEdge && (
          <>
            {/* Aggregated Edge Overview */}
            <div style={{ background: 'var(--bg-card)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Aggregated Flow Edge (Virtual Aggregate)
                  </div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                    {selectedEdge.source} ➔ {selectedEdge.target}
                  </div>
                </div>
                <span className={`badge ${selectedEdge.risk_score >= 60 ? 'badge-critical' : 'badge-low'}`}>
                  Risk {selectedEdge.risk_score}
                </span>
              </div>

              <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Total Flows Represented:</span>
                  <div style={{ fontWeight: 700 }}>{selectedEdge.flow_count} flows</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Protocol / App:</span>
                  <div style={{ fontWeight: 700 }}>{selectedEdge.protocol || 'TCP'} / HTTPS</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Outbound Bytes:</span>
                  <div style={{ fontWeight: 700, color: selectedEdge.bytes_sent > 10_000_000 ? 'var(--accent-rose)' : 'inherit' }}>
                    {((selectedEdge.bytes_sent || 0) / 1_000_000).toFixed(2)} MB
                  </div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Category:</span>
                  <div style={{ fontWeight: 700 }}>{selectedEdge.category || 'general'}</div>
                </div>
              </div>
            </div>

            {/* Evidence & MITRE Rationale */}
            <div style={{ background: 'var(--bg-card)', padding: 14, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <FileText size={14} /> Supporting Evidence & Rationale
              </div>
              <ul style={{ marginTop: 8, paddingLeft: 18, fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                <li>Aggregated volume: {((selectedEdge.bytes_sent || 0) / 1_000_000).toFixed(1)} MB transmitted</li>
                <li>Destination type: {selectedEdge.category} (RFC 5737 simulated cloud)</li>
                <li>Allowlist status: {selectedEdge.allowlisted ? 'Allowlisted policy match' : 'Non-allowlisted transfer'}</li>
                <li>MITRE ATT&CK: T1048.003 (Exfiltration Over Protocol)</li>
              </ul>
            </div>
          </>
        )}
      </div>

      {/* Footer Actions */}
      <div
        style={{
          padding: 16,
          borderTop: '1px solid var(--border-color)',
          background: 'var(--bg-secondary)',
          display: 'flex',
          gap: 8,
        }}
      >
        <button
          onClick={() => alert('Starting investigation case bundle export...')}
          style={{
            flex: 1,
            background: 'var(--accent-cyan)',
            color: '#070d1e',
            fontWeight: 700,
            padding: '8px 12px',
            borderRadius: 6,
            fontSize: '0.82rem',
          }}
        >
          Open Case Bundle
        </button>
        <button
          onClick={onClose}
          style={{
            background: 'var(--bg-card)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-color)',
            padding: '8px 12px',
            borderRadius: 6,
            fontSize: '0.82rem',
          }}
        >
          Dismiss
        </button>
      </div>
    </div>
  );
};
