import React, { useState } from 'react';
import { Sliders, Play, RotateCcw, ShieldAlert, ArrowRight, Zap, CheckCircle2 } from 'lucide-react';

export const ScenarioLabView: React.FC = () => {
  const [outboundMB, setOutboundMB] = useState(250);
  const [destNovelty, setDestNovelty] = useState(true);
  const [isOffHours, setIsOffHours] = useState(true);
  const [dnsQueries, setDnsQueries] = useState(150);
  const [failedLogins, setFailedLogins] = useState(4);
  const [isAllowlisted, setIsAllowlisted] = useState(false);
  const [assetTier, setAssetTier] = useState(3);

  // Calculate simulated risk in real-time
  const subVol = Math.min(1.0, 1.0 / (1.0 + Math.exp(-0.000002 * (outboundMB * 1_000_000 - 1_000_000))));
  const subNov = destNovelty ? 0.85 : 0.15;
  const subAuth = Math.min(1.0, failedLogins * 0.25);
  const subDns = Math.min(1.0, (dnsQueries / 500) * 0.8);
  const subTiming = isOffHours ? 0.85 : 0.15;

  let contextMult = isAllowlisted ? 0.35 : 1.0;
  if (assetTier === 3) contextMult *= 1.3;

  const weightedSum = 0.30 * subVol + 0.25 * subNov + 0.20 * subAuth + 0.15 * subDns + 0.10 * subTiming;
  const simulatedScore = Math.min(100.0, Math.round(weightedSum * 100.0 * contextMult * 10) / 10);
  const baselineScore = 24.5;
  const delta = Math.round((simulatedScore - baselineScore) * 10) / 10;

  const severity = simulatedScore >= 80 ? 'CRITICAL' : simulatedScore >= 60 ? 'HIGH' : simulatedScore >= 35 ? 'MEDIUM' : 'LOW';

  return (
    <div style={{ padding: 24, height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Title */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Sliders style={{ color: 'var(--accent-cyan)' }} /> What-If Scenario Simulation Lab
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
          Simulate behavioral parameter deviations to inspect detector triggers and risk escalation without modifying production telemetry.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
        {/* Sliders Form */}
        <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--accent-cyan)', borderBottom: '1px solid var(--border-color)', paddingBottom: 8 }}>
            Scenario Simulation Parameters
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 6 }}>
              <span>Outbound Transfer Volume:</span>
              <strong style={{ color: 'var(--accent-cyan)' }}>{outboundMB} MB</strong>
            </div>
            <input type="range" min="1" max="1000" value={outboundMB} onChange={(e) => setOutboundMB(Number(e.target.value))} style={{ width: '100%' }} />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 6 }}>
              <span>Failed Authentication Attempts:</span>
              <strong style={{ color: 'var(--accent-rose)' }}>{failedLogins} attempts</strong>
            </div>
            <input type="range" min="0" max="15" value={failedLogins} onChange={(e) => setFailedLogins(Number(e.target.value))} style={{ width: '100%' }} />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 6 }}>
              <span>DNS Query Spike:</span>
              <strong style={{ color: 'var(--accent-amber)' }}>{dnsQueries} queries/hr</strong>
            </div>
            <input type="range" min="10" max="800" value={dnsQueries} onChange={(e) => setDnsQueries(Number(e.target.value))} style={{ width: '100%' }} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8rem', cursor: 'pointer' }}>
              <input type="checkbox" checked={destNovelty} onChange={(e) => setDestNovelty(e.target.checked)} />
              First-Seen Destination (Novelty)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8rem', cursor: 'pointer' }}>
              <input type="checkbox" checked={isOffHours} onChange={(e) => setIsOffHours(e.target.checked)} />
              Off-Hours Operation (02:00 AM)
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8rem', cursor: 'pointer' }}>
              <input type="checkbox" checked={isAllowlisted} onChange={(e) => setIsAllowlisted(e.target.checked)} />
              Sanctioned Operation (Allowlisted)
            </label>
            <div>
              <span style={{ fontSize: '0.8rem', display: 'block', marginBottom: 4 }}>Asset Criticality:</span>
              <select value={assetTier} onChange={(e) => setAssetTier(Number(e.target.value))} style={{ width: '100%' }}>
                <option value="1">Tier 1 — Standard Workstation</option>
                <option value="2">Tier 2 — Sensitive Financial Server</option>
                <option value="3">Tier 3 — Domain Controller / Exec</option>
              </select>
            </div>
          </div>
        </div>

        {/* Real-Time Prediction & Risk Delta Card */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Simulation Risk Projection</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginTop: 8 }}>
              <div style={{ fontSize: '2.8rem', fontWeight: 900, color: severity === 'CRITICAL' ? 'var(--accent-rose)' : severity === 'HIGH' ? 'var(--accent-amber)' : 'var(--accent-cyan)' }}>
                {simulatedScore}
              </div>
              <span className={`badge badge-${severity.toLowerCase()}`} style={{ fontSize: '0.85rem' }}>
                {severity}
              </span>
            </div>

            <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>Baseline: 24.5</span>
              <ArrowRight size={14} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontWeight: 700, color: delta > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
                {delta > 0 ? `+${delta}` : delta} Risk Delta
              </span>
            </div>

            <div style={{ marginTop: 16, borderTop: '1px solid var(--border-color)', paddingTop: 14, fontSize: '0.8rem' }}>
              <div style={{ fontWeight: 600, color: 'var(--accent-cyan)', marginBottom: 6 }}>Triggered Analytical Detectors:</div>
              <ul style={{ paddingLeft: 18, color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                {outboundMB > 100 && <li>Volume Anomaly: {outboundMB} MB transfer (Score: {subVol.toFixed(2)})</li>}
                {destNovelty && <li>Destination Novelty: Unseen external cloud endpoint (Score: {subNov.toFixed(2)})</li>}
                {failedLogins > 2 && <li>Authentication Burst: {failedLogins} failed Kerberos attempts</li>}
                {isOffHours && <li>Temporal Baseline: Execution outside active hours window</li>}
                {assetTier === 3 && <li>Critical Asset Multiplier: 1.30x applied</li>}
                {isAllowlisted && <li>Allowlist Policy: 0.35x dampening applied</li>}
              </ul>
            </div>
          </div>

          <div className="glass-panel" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
            <ShieldAlert size={28} style={{ color: simulatedScore >= 35 ? 'var(--accent-rose)' : 'var(--accent-emerald)' }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>
                {simulatedScore >= 35 ? 'Investigation Case Opened' : 'Below SOC Alert Threshold'}
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {simulatedScore >= 35
                  ? `Entity would be enqueued as Priority ${simulatedScore >= 80 ? 'Rank 1' : 'Rank 4'} in SOC triage queue.`
                  : 'Traffic is treated as benign baseline activity.'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
