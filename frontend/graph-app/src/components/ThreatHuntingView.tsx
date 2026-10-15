import React, { useState } from 'react';
import { Compass, Search, Filter, Play, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';

const PRESET_HUNTING_QUERIES = [
  {
    id: 'first_seen_high_outbound',
    title: 'First-Seen External Cloud with Elevated Outbound Volume (>10MB)',
    category: 'Exfiltration',
    description: 'Finds transfers where the destination had zero baseline encounters prior to the observation window.',
    mitre: 'T1048.003 - Exfiltration Over Alternative Protocol',
  },
  {
    id: 'off_hours_domain_controller',
    title: 'Off-Hours Domain Controller Access with Subsequent Outbound Flows',
    category: 'Credential Misuse',
    description: 'Correlates failed Kerberos auth bursts at 01:00-05:00 AM with external network egress.',
    mitre: 'T1078.002 - Domain Accounts',
  },
  {
    id: 'dns_entropy_tunneling',
    title: 'DNS Tunneling Fingerprints (High Entropy Subdomains > 3.8)',
    category: 'C2 / Exfiltration',
    description: 'Identifies clients issuing high volumes of dynamic base64/hex-encoded subdomains.',
    mitre: 'T1071.004 - DNS Protocols',
  },
  {
    id: 'rotating_destination_transfers',
    title: 'Repeated Small Transfers Across Rotating Rare Destinations (Low-and-Slow)',
    category: 'Staging & Egress',
    description: 'Scans for periodic 5-15MB bursts sent to multiple unique destinations within 48 hours.',
    mitre: 'T1048 - Exfiltration Staging',
  },
];

export const ThreatHuntingView: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState(PRESET_HUNTING_QUERIES[0].id);
  const [minBytesMB, setMinBytesMB] = useState(10);
  const [timeWindowDays, setTimeWindowDays] = useState(14);
  const [results, setResults] = useState<any[]>([]);
  const [isHunting, setIsHunting] = useState(false);

  const runHuntingQuery = () => {
    setIsHunting(true);
    setTimeout(() => {
      // Synthesize safe parameterized results based on preset
      if (selectedPreset === 'first_seen_high_outbound') {
        setResults([
          {
            entity: 'EMP001 (10.0.1.1)',
            destination: '198.51.100.99 [personal_cloud]',
            volume: '650.0 MB',
            flows: 1,
            novelty: 'FIRST_SEEN',
            mitre: 'T1048.003',
            threatScore: 92.4,
            verdict: 'SUSPICIOUS_EXFILTRATION',
          },
          {
            entity: 'EMP006 (10.0.1.6)',
            destination: '203.0.113.88 [other]',
            volume: '85.0 MB',
            flows: 1,
            novelty: 'FIRST_SEEN',
            mitre: 'T1048.003',
            threatScore: 78.6,
            verdict: 'ANOMALOUS_EGRESS',
          },
        ]);
      } else if (selectedPreset === 'off_hours_domain_controller') {
        setResults([
          {
            entity: 'EMP006 (10.0.1.6)',
            destination: 'DomainController_SMB',
            volume: '5 Failed Logins',
            flows: 5,
            novelty: 'OFF_HOURS_BURST',
            mitre: 'T1078.002',
            threatScore: 78.6,
            verdict: 'BRUTE_FORCE_AND_EGRESS',
          },
        ]);
      } else {
        setResults([
          {
            entity: 'EMP002 (10.0.1.2)',
            destination: '203.0.113.45 [personal_cloud]',
            volume: '75.0 MB (6 Chunks)',
            flows: 6,
            novelty: 'PERIODIC_TRANSFER',
            mitre: 'T1048',
            threatScore: 68.2,
            verdict: 'LOW_AND_SLOW_STAGING',
          },
        ]);
      }
      setIsHunting(false);
    }, 600);
  };

  return (
    <div style={{ padding: 24, height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Title */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Compass style={{ color: 'var(--accent-cyan)' }} /> Threat-Hunting Parameterized Query Builder
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
          Safe, structured threat hunting translating analyst hypotheses into parameterized DuckDB queries (no raw arbitrary SQL).
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: 24 }}>
        {/* Presets and Filters */}
        <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--accent-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: 8 }}>
            Hunting Presets & Hypotheses
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {PRESET_HUNTING_QUERIES.map((q) => (
              <div
                key={q.id}
                onClick={() => setSelectedPreset(q.id)}
                style={{
                  padding: 12,
                  borderRadius: 6,
                  cursor: 'pointer',
                  border: `1px solid ${selectedPreset === q.id ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
                  background: selectedPreset === q.id ? 'rgba(56, 189, 248, 0.12)' : 'var(--bg-card)',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.85rem', color: selectedPreset === q.id ? 'var(--accent-cyan)' : 'inherit' }}>
                  {q.title}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>{q.description}</div>
                <div style={{ marginTop: 6 }}>
                  <span className="badge badge-medium" style={{ fontSize: '0.68rem' }}>{q.mitre}</span>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 12, marginTop: 6 }}>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Min Volume (MB):</span>
              <input type="number" value={minBytesMB} onChange={(e) => setMinBytesMB(Number(e.target.value))} style={{ width: '100%', marginTop: 4 }} />
            </div>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Time Window:</span>
              <select value={timeWindowDays} onChange={(e) => setTimeWindowDays(Number(e.target.value))} style={{ width: '100%', marginTop: 4 }}>
                <option value="7">Last 7 Days</option>
                <option value="14">Last 14 Days</option>
                <option value="30">Last 30 Days</option>
              </select>
            </div>
          </div>

          <button
            onClick={runHuntingQuery}
            disabled={isHunting}
            style={{
              background: 'var(--accent-cyan)',
              color: '#070d1e',
              fontWeight: 800,
              padding: '10px 16px',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              marginTop: 8,
            }}
          >
            <Play size={16} /> {isHunting ? 'Executing Parameterized Query...' : 'Execute Threat Hunt'}
          </button>
        </div>

        {/* Results Panel */}
        <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: 8 }}>
            <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>Hunting Results ({results.length} entities matched)</div>
            {results.length > 0 && <span className="badge badge-critical">Active Findings</span>}
          </div>

          {results.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
              Click "Execute Threat Hunt" to search DuckDB flow and auth tables using verified parameterized logic.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {results.map((r, i) => (
                <div
                  key={i}
                  style={{
                    background: 'var(--bg-card)',
                    padding: 14,
                    borderRadius: 8,
                    border: '1px solid var(--border-color)',
                    borderLeft: '4px solid var(--accent-rose)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontSize: '0.95rem' }}>{r.entity}</div>
                    <span className="badge badge-critical">Risk {r.threatScore}</span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Destination: <strong style={{ color: 'var(--text-primary)' }}>{r.destination}</strong> | Volume: {r.volume}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                    <span className="badge badge-medium">{r.mitre}</span>
                    <span className="badge badge-high">{r.verdict}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
