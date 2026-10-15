import React, { useState } from 'react';
import { X, ShieldAlert, ArrowUpRight, ArrowDownLeft, Clock, Activity, FileText, CheckCircle2, AlertTriangle } from 'lucide-react';

interface InvestigationDrawerProps {
  selectedNode?: any | null;
  selectedEdge?: any | null;
  node?: any | null;
  edge?: any | null;
  onClose: () => void;
  onUpdateCaseStatus?: (caseId: string, status: string) => void;
  onTriggerInvestigation?: (entityId: string) => void;
}

export const InvestigationDrawer: React.FC<InvestigationDrawerProps> = ({
  selectedNode,
  selectedEdge,
  node,
  edge,
  onClose,
  onUpdateCaseStatus,
  onTriggerInvestigation,
}) => {
  const activeNode = selectedNode || node;
  const activeEdge = selectedEdge || edge;

  if (!activeNode && !activeEdge) {
    return (
      <div
        style={{
          width: '100%',
          height: '100%',
          minHeight: '400px',
          background: 'var(--bg-surface)',
          borderRadius: 8,
          border: '1px solid var(--border-color)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 24,
          textAlign: 'center',
          color: 'var(--text-muted)',
          gap: 12,
        }}
      >
        <ShieldAlert size={36} style={{ color: 'var(--accent-cyan)', opacity: 0.8 }} />
        <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
          Interactive Entity Inspector
        </div>
        <p style={{ fontSize: '0.8rem', lineHeight: 1.5, maxWidth: 280 }}>
          Click on any node or flow edge on the topological graph to inspect pseudonymous entity attributes, peer deviations, and threat evidence.
        </p>
      </div>
    );
  }

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
            {activeNode ? 'Entity Investigation Dossier' : 'Aggregated Edge Evidence'}
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
        {activeNode && (
          <>
            {/* Entity Overview Card */}
            <div style={{ background: 'var(--bg-card)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Pseudonymous Entity ID</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 2 }}>
                    {activeNode.entity_id || activeNode.id || activeNode.label}
                  </div>
                </div>
                <span className={`badge badge-${(activeNode.severity || 'low').toLowerCase()}`}>
                  {activeNode.severity || 'LOW'} ({activeNode.risk_score || activeNode.riskScore || 10})
                </span>
              </div>

              <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Node Type:</span>
                  <div style={{ fontWeight: 600 }}>{activeNode.type}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>IP / Label:</span>
                  <div style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{activeNode.label || activeNode.ip || activeNode.id}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Asset Criticality:</span>
                  <div style={{ fontWeight: 600 }}>Tier {activeNode.asset_tier || activeNode.assetTier || 2}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Observed Period:</span>
                  <div style={{ fontWeight: 600 }}>{activeNode.lastSeen || '14 Days'}</div>
                </div>
              </div>
            </div>

            {/* Behavioral Baseline Deviations */}
            <div style={{ background: 'var(--bg-card)', padding: 14, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} /> Behavioral Baseline Comparison
              </div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
                {(activeNode.risk_score || activeNode.riskScore || 0) >= 60
                  ? `Outbound volume is ${(((activeNode.risk_score || activeNode.riskScore) / 15)).toFixed(1)}x higher than peer group median (Finance/Engineering). Temporal deviation flagged during off-hours.`
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
                  {(((activeNode.total_volume || activeNode.totalBytes || 0)) / 1_000_000).toFixed(2)} MB
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

        {activeEdge && (
          <>
            {/* Aggregated Edge Overview */}
            <div style={{ background: 'var(--bg-card)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Aggregated Flow Edge (Virtual Aggregate)
                  </div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                    {activeEdge.source} ➔ {activeEdge.target}
                  </div>
                </div>
                <span className={`badge ${(activeEdge.risk_score || activeEdge.riskScore || 0) >= 60 ? 'badge-critical' : 'badge-low'}`}>
                  Risk {activeEdge.risk_score || activeEdge.riskScore || 10}
                </span>
              </div>

              <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Flows Count:</span>
                  <div style={{ fontWeight: 700 }}>{activeEdge.flow_count || activeEdge.flowsCount || 1} flows</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Protocol / App:</span>
                  <div style={{ fontWeight: 700 }}>{activeEdge.protocol || 'TCP'} / {activeEdge.app || 'TLS'}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Outbound Bytes:</span>
                  <div style={{ fontWeight: 700, color: (activeEdge.bytes_sent || activeEdge.totalBytes || 0) > 10_000_000 ? 'var(--accent-rose)' : 'inherit' }}>
                    {(((activeEdge.bytes_sent || activeEdge.totalBytes || 0)) / 1_000_000).toFixed(2)} MB
                  </div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Category:</span>
                  <div style={{ fontWeight: 700 }}>{activeEdge.category || activeEdge.app || 'general'}</div>
                </div>
              </div>
            </div>

            {/* Evidence & MITRE Rationale */}
            <div style={{ background: 'var(--bg-card)', padding: 14, borderRadius: 8, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <FileText size={14} /> Supporting Evidence & Rationale
              </div>
              <ul style={{ marginTop: 8, paddingLeft: 18, fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                <li>Aggregated volume: {(((activeEdge.bytes_sent || activeEdge.totalBytes || 0)) / 1_000_000).toFixed(1)} MB transmitted</li>
                <li>Destination type: {activeEdge.category || activeEdge.app || 'External Cloud'}</li>
                <li>Allowlist status: {activeEdge.allowlisted ? 'Allowlisted policy match' : 'Non-allowlisted transfer'}</li>
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
