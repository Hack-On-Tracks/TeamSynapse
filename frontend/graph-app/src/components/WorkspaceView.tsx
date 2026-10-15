import React, { useState, useEffect } from 'react';
import {
  Activity,
  ArrowDown,
  ArrowDownToLine,
  ArrowRight,
  Bell,
  Building2,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Download,
  EyeOff,
  FileCheck2,
  Fingerprint,
  Globe2,
  LayoutGrid,
  LockKeyhole,
  Menu,
  Shield,
  ShieldCheck,
  Users,
  X,
  Layers,
  Play,
  Zap,
  BarChart3,
  RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { TrafficChart } from '@/components/traffic-chart';
import { NetworkFlows, RelatedFlows, useFlowStream } from '@/components/network-flows';
import { demoCases, downloadEvidence, type CaseRecord, type FlowRecord } from '@/lib/demo-cases';
import { fetchLiveCases, updateCaseStatus, fetchGraphSummary, fetchAuditLogs, type GraphSummary, type AuditLogEntry } from '@/lib/api';

import { CytoscapeGraph } from './CytoscapeGraph';
import { InvestigationDrawer } from './InvestigationDrawer';
import { ReplayController } from './ReplayController';
import { ScenarioLabView } from './ScenarioLabView';
import { EvaluationLabView } from './EvaluationLabView';
import { ThreatHuntingView } from './ThreatHuntingView';

export type WorkspaceTab =
  | 'Overview'
  | 'Investigations'
  | 'Network Graph'
  | 'Temporal Replay'
  | 'Scenario Lab'
  | 'Evaluation Lab'
  | 'Activity log'
  | 'Privacy & controls';

interface WorkspaceProps {
  initialView?: WorkspaceTab;
  graphElements: any;
  onRefreshGraph?: () => void;
  apiConnected: boolean;
}

export const WorkspaceView: React.FC<WorkspaceProps> = ({
  initialView = 'Overview',
  graphElements,
  onRefreshGraph,
  apiConnected,
}) => {
  const [view, setView] = useState<WorkspaceTab>(initialView);
  const [cases, setCases] = useState<CaseRecord[]>(demoCases);
  const [summary, setSummary] = useState<GraphSummary | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [period, setPeriod] = useState('7 days');
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [note, setNote] = useState('');
  const [message, setMessage] = useState('');
  const [info, setInfo] = useState<'notifications' | 'help' | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  // Cytoscape selection & replay states
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<any | null>(null);
  const [currentFrame, setCurrentFrame] = useState(5);
  const [totalFrames, setTotalFrames] = useState(12);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [currentTimestamp, setCurrentTimestamp] = useState('2026-10-15 03:15:00 UTC');
  const [scenarios] = useState<string[]>([
    'ALL_SCENARIOS',
    'high_volume_exfiltration',
    'low_and_slow',
    'approved_backup',
    'dns_entropy',
  ]);
  const [selectedScenario, setSelectedScenario] = useState('ALL_SCENARIOS');

  const flowStream = useFlowStream();

  // Load cases and summary from FastAPI backend
  const refreshData = async () => {
    const caseResult = await fetchLiveCases();
    setCases(caseResult.cases);

    const sum = await fetchGraphSummary();
    if (sum) setSummary(sum);

    const logs = await fetchAuditLogs();
    if (logs && logs.length > 0) setAuditLogs(logs);
  };

  useEffect(() => {
    refreshData();
  }, []);

  function openCase(id: string) {
    setSelectedFlow(null);
    setSelectedCase(cases.find(c => c.id === id) ?? null);
    setNote('');
  }

  const openCount = cases.filter(c => c.status === 'Open' || c.status === 'Investigating').length;

  async function handleDecide(status: CaseRecord['status']) {
    if (!selectedCase) return;
    const targetId = selectedCase.id;

    // Optimistically update UI
    setCases(prev => prev.map(c => (c.id === targetId ? { ...c, status, analystNote: note } : c)));

    // Send decision to backend
    const res = await updateCaseStatus(targetId, status, note);
    setMessage(`${targetId} marked as ${status.toLowerCase()}. ${res.message}`);
    setSelectedCase(null);
    setNote('');

    // Refresh audit logs
    const logs = await fetchAuditLogs();
    if (logs.length > 0) setAuditLogs(logs);
  }

  const navItems = [
    { title: 'Overview' as WorkspaceTab, icon: LayoutGrid },
    { title: 'Investigations' as WorkspaceTab, icon: Shield, count: openCount },
    { title: 'Network Graph' as WorkspaceTab, icon: Layers },
    { title: 'Temporal Replay' as WorkspaceTab, icon: Play },
    { title: 'Scenario Lab' as WorkspaceTab, icon: Zap },
    { title: 'Evaluation Lab' as WorkspaceTab, icon: BarChart3 },
    { title: 'Activity log' as WorkspaceTab, icon: Activity },
    { title: 'Privacy & controls' as WorkspaceTab, icon: Fingerprint },
  ];

  const filteredCases = cases.filter(c => {
    if (filterStatus === 'ALL') return true;
    return c.status.toLowerCase() === filterStatus.toLowerCase();
  });

  return (
    <div className="app-shell">
      {/* Sidebar Navigation */}
      <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="brand cursor-pointer" onClick={() => setView('Overview')}>
          <ShieldCheck className="brand-mark" strokeWidth={1.8} />
          CipherSentinel
        </div>

        <div className="workspace-picker">
          <span className="workspace-icon">
            <Building2 size={15} />
          </span>
          <div>
            <div className="text-xs font-semibold">Acme workspace</div>
            <div className="text-[10px] text-muted-foreground mt-0.5">Security operations</div>
          </div>
          <LockKeyhole size={12} className="ml-auto text-muted-foreground" />
        </div>

        <div className="nav-label">Workspace</div>
        <nav>
          {navItems.map(item => (
            <button
              type="button"
              key={item.title}
              className={`nav-item w-full text-left cursor-pointer border-0 bg-transparent ${view === item.title ? 'active' : ''}`}
              onClick={() => {
                setView(item.title);
                setMobileOpen(false);
              }}
            >
              <item.icon size={16} strokeWidth={1.7} />
              <span>{item.title}</span>
              {item.count !== undefined && item.count > 0 && <span className="nav-count">{item.count}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="privacy-note">
            <div className="flex items-center gap-2 text-xs font-semibold">
              <LockKeyhole size={14} className="text-primary" />
              Privacy comes first
            </div>
            <p>
              Metadata only. Identities protected.
              <br />
              Every decision stays human.
            </p>
          </div>
          <div className="profile">
            <div className="avatar">JS</div>
            <div>
              <div className="text-xs font-semibold">Janhvi S.</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">Security analyst</div>
            </div>
            <ShieldCheck size={15} className="ml-auto text-muted-foreground" />
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-area">
        {/* Top Header Bar */}
        <header className="topbar">
          <div className="topbar-left">
            <Button
              variant="ghost"
              size="icon"
              className="mobile-menu"
              aria-label="Toggle navigation"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X size={16} /> : <Menu size={16} />}
            </Button>
            <span>Workspace</span>
            <ChevronRight size={12} />
            <span className="text-foreground font-medium">{view}</span>
          </div>

          <div className="topbar-actions">
            <span className="system-status flex items-center gap-1.5">
              <span className={`status-dot ${apiConnected ? '' : 'paused'}`} />
              {apiConnected ? 'Live Backend Connected' : 'Local Session Mode'}
            </span>
            <Button
              variant="ghost"
              size="icon"
              title="Refresh Telemetry"
              aria-label="Refresh"
              onClick={() => {
                refreshData();
                onRefreshGraph?.();
              }}
            >
              <RefreshCw size={15} />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              title="Notifications"
              aria-label="Notifications"
              onClick={() => setInfo('notifications')}
            >
              <Bell size={16} />
            </Button>
            <Button variant="ghost" size="icon" title="Help" aria-label="Help" onClick={() => setInfo('help')}>
              <CircleHelp size={16} />
            </Button>
          </div>
        </header>

        {/* Page Content Body */}
        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="flex items-center gap-10">
                <h1>{view === 'Overview' ? 'Security overview' : view}</h1>
                <span className="demo-tag">{apiConnected ? 'Live analytical database' : 'Simulated telemetry'}</span>
              </div>
              <p className="subtitle">
                {view === 'Overview'
                  ? 'A clear view of the signals and threat anomalies that need your attention.'
                  : view === 'Investigations'
                  ? 'Review evidence bundles, verify behavioral signals, and record analyst decisions.'
                  : view === 'Network Graph'
                  ? 'Cytoscape-powered topological analysis with risk indicators and community clusters.'
                  : view === 'Temporal Replay'
                  ? 'Deterministic frame playback reconstructing communication sequences over time.'
                  : view === 'Scenario Lab'
                  ? 'Test detector robustness and investigate synthetic exfiltration scenarios.'
                  : view === 'Evaluation Lab'
                  ? 'Real-time performance evaluation, ROC AUC metrics, and detector latency.'
                  : view === 'Activity log'
                  ? 'Transparent, immutable record of workspace reviews and security events.'
                  : 'Protection for your organisation. Respect for your people.'}
              </p>
            </div>

            {(view === 'Overview' || view === 'Investigations') && (
              <div className="heading-actions">
                <Button variant="outline" size="sm" onClick={() => setPeriod(period === '7 days' ? '30 days' : '7 days')}>
                  <Clock3 size={13} />
                  Last {period}
                  <ChevronDown size={13} />
                </Button>
                <Button variant="outline" size="sm" onClick={() => downloadEvidence(cases)}>
                  <ArrowDownToLine size={13} />
                  Export report
                </Button>
              </div>
            )}
          </div>

          {message && (
            <div className="notice" role="status">
              {message}
            </div>
          )}

          {/* VIEW: OVERVIEW */}
          {view === 'Overview' && (
            <>
              <section className="metrics" aria-label="Security summary">
                <div className="metric">
                  <div className="metric-label">
                    Open investigations
                    <Shield size={15} />
                  </div>
                  <div className="metric-value">
                    {(summary?.open_cases ?? openCount).toString().padStart(2, '0')}
                  </div>
                  <div className="metric-note">
                    <span className="warning">
                      {cases.filter(c => c.severity === 'high').length} high priority
                    </span>
                    <span>· requires review</span>
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Monitored entities
                    <Users size={15} />
                  </div>
                  <div className="metric-value">
                    {summary?.node_count ?? 80}
                    <span className="text-base text-muted-foreground font-normal"> / {summary?.node_count ?? 80}</span>
                  </div>
                  <div className="metric-note">
                    <span className="status-dot" />
                    Active across {summary?.unique_sources ?? 4} peer groups
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Outbound data
                    <Globe2 size={15} />
                  </div>
                  <div className="metric-value">
                    {summary?.total_bytes
                      ? (summary.total_bytes / (1024 * 1024 * 1024)).toFixed(1)
                      : period === '7 days'
                      ? '24.8'
                      : '106.2'}
                    <span className="text-base text-muted-foreground font-normal"> GB</span>
                  </div>
                  <div className="metric-note">
                    <ArrowDown size={11} className="positive" />
                    <span className="positive">8.2%</span> vs. previous baseline
                  </div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Signal confidence
                    <ShieldCheck size={15} />
                  </div>
                  <div className="metric-value">
                    94.2<span className="text-base text-muted-foreground font-normal">%</span>
                  </div>
                  <div className="metric-note">DuckDB analytical telemetry is healthy</div>
                </div>
              </section>

              <div className="analysis-grid">
                <section className="chart-panel">
                  <div className="panel-header">
                    <div>
                      <h2>Outbound traffic</h2>
                      <p className="panel-subtitle">Data sent over time compared with the peer baseline</p>
                    </div>
                    <div className="segmented">
                      {['7 days', '30 days'].map(p => (
                        <button
                          key={p}
                          type="button"
                          className={`segment cursor-pointer border-0 ${period === p ? 'selected' : ''}`}
                          onClick={() => setPeriod(p)}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="chart-wrap">
                    <TrafficChart period={period} />
                  </div>
                  <div className="chart-legend">
                    <span>
                      <i className="legend-key" />
                      Outbound traffic
                    </span>
                    <span>
                      <i className="legend-key baseline" />
                      Peer baseline
                    </span>
                  </div>
                  <div className="chart-footer">
                    <ShieldCheck size={12} />
                    Encrypted metadata analysed without inspecting message contents or payloads.
                  </div>
                </section>

                <section className="attention-panel">
                  <div className="panel-header">
                    <h2>Worth a closer look</h2>
                    <span className="severity high">High priority</span>
                  </div>
                  <div className="attention-body">
                    <span className="case-ref">
                      {cases[0]?.id ?? 'CS-0042'} · {cases[0]?.user ?? 'USR-028'}
                    </span>
                    <h3 className="attention-title">
                      {cases[0]?.title ?? 'Small transfers. A growing pattern.'}
                    </h3>
                    <p className="attention-description">
                      Repeated uploads to uncommon destination over {cases[0]?.days ?? 14} days. The cumulative activity diverges significantly from peer baselines.
                    </p>
                    <div className="attention-meta">
                      <div>
                        <label>Risk index</label>
                        <strong className="danger">
                          {cases[0]?.risk ?? 92}{' '}
                          <span className="text-muted-foreground font-normal">/ 100</span>
                        </strong>
                      </div>
                      <div>
                        <label>Confidence</label>
                        <strong>{cases[0]?.confidence ?? 94}%</strong>
                      </div>
                      <div>
                        <label>Total volume</label>
                        <strong>{cases[0]?.bytes ?? '284 MB'}</strong>
                      </div>
                    </div>
                    <Button
                      className="w-full cursor-pointer"
                      size="sm"
                      onClick={() => {
                        setSelectedCase(cases[0] ?? null);
                        setNote(cases[0]?.analystNote ?? '');
                      }}
                    >
                      Review investigation
                      <ArrowRight size={13} />
                    </Button>
                  </div>
                </section>
              </div>

              {/* Live Flow Stream Table */}
              <section>
                <NetworkFlows
                  stream={flowStream}
                  cases={cases}
                  selected={selectedFlow}
                  onSelect={setSelectedFlow}
                  onOpenCase={openCase}
                />
              </section>
            </>
          )}

          {/* VIEW: INVESTIGATIONS */}
          {view === 'Investigations' && (
            <div className="space-y-6">
              <div className="queue">
                <div className="queue-toolbar">
                  <div className="filter-tabs">
                    {['ALL', 'Open', 'Investigating', 'Confirmed', 'Dismissed'].map(st => (
                      <button
                        key={st}
                        type="button"
                        className={`filter cursor-pointer rounded px-2.5 py-1 text-xs border border-transparent ${
                          filterStatus === st ? 'selected bg-secondary font-semibold' : 'text-muted-foreground hover:bg-muted'
                        }`}
                        onClick={() => setFilterStatus(st)}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="table-scroll">
                  <table className="case-table">
                    <thead>
                      <tr>
                        <th>Case ID</th>
                        <th>User / Entity</th>
                        <th>Investigation Title</th>
                        <th>Destination</th>
                        <th>Pattern</th>
                        <th>Risk Score</th>
                        <th>Confidence</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCases.map(c => (
                        <tr
                          key={c.id}
                          onClick={() => {
                            setSelectedCase(c);
                            setNote(c.analystNote ?? '');
                          }}
                        >
                          <td className="font-mono font-semibold">{c.id}</td>
                          <td className="font-semibold">{c.user}</td>
                          <td>
                            <div className="case-cell-title">{c.title}</div>
                            <div className="case-cell-sub">
                              {c.team} · {c.category}
                            </div>
                          </td>
                          <td className="font-mono text-xs">{c.destination}</td>
                          <td>{c.pattern}</td>
                          <td>
                            <div className="risk-cell">
                              <span>{c.risk}</span>
                              <div
                                className={`risk-track ${
                                  c.risk >= 70 ? 'high' : c.risk >= 40 ? 'medium' : 'low'
                                }`}
                              >
                                <progress max={100} value={c.risk} />
                              </div>
                            </div>
                          </td>
                          <td>{c.confidence}%</td>
                          <td>
                            <span
                              className={`severity ${
                                c.status === 'Confirmed'
                                  ? 'high'
                                  : c.status === 'Investigating'
                                  ? 'medium'
                                  : 'low'
                              }`}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td>
                            <Button size="sm" variant="outline">
                              Review
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredCases.length === 0 && (
                    <div className="empty-state">No investigations match this status filter.</div>
                  )}
                </div>
              </div>

              {/* Related Network Flows Component */}
              <section className="mt-8">
                <NetworkFlows
                  stream={flowStream}
                  cases={cases}
                  selected={selectedFlow}
                  onSelect={setSelectedFlow}
                  onOpenCase={openCase}
                />
              </section>
            </div>
          )}

          {/* VIEW: NETWORK GRAPH */}
          {view === 'Network Graph' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
              <div
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Temporal Topology Graph
                  </span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                    {graphElements.nodes.length} nodes &bull; {graphElements.edges.length} flow edges
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Button variant="outline" size="sm" onClick={onRefreshGraph} style={{ cursor: 'pointer', display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <RefreshCw size={12} />
                    Reset Graph
                  </Button>
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(0, 1fr) 380px',
                  gap: '16px',
                  height: '560px',
                  minHeight: '560px',
                  width: '100%',
                }}
              >
                <div
                  style={{
                    height: '100%',
                    minHeight: '560px',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    background: '#060b17',
                    position: 'relative',
                  }}
                >
                  <CytoscapeGraph
                    elements={graphElements}
                    onNodeSelect={setSelectedNode}
                    onEdgeSelect={setSelectedEdge}
                    filterRiskThreshold={0}
                    selectedNodeType="all"
                  />
                </div>

                <div
                  style={{
                    height: '100%',
                    minHeight: '560px',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    overflowY: 'auto',
                    background: 'var(--bg-card)',
                  }}
                >
                  <InvestigationDrawer
                    selectedNode={selectedNode}
                    selectedEdge={selectedEdge}
                    onClose={() => {
                      setSelectedNode(null);
                      setSelectedEdge(null);
                    }}
                    onTriggerInvestigation={entityId => {
                      setView('Investigations');
                      const found = cases.find(c => c.user === entityId || c.id === entityId);
                      if (found) {
                        setSelectedCase(found);
                        setNote(found.analystNote ?? '');
                      }
                    }}
                  />
                </div>
              </div>
            </div>
          )}

          {/* VIEW: TEMPORAL REPLAY */}
          {view === 'Temporal Replay' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
              <ReplayController
                currentFrame={currentFrame}
                totalFrames={totalFrames}
                isPlaying={isPlaying}
                speed={speed}
                currentTimestamp={currentTimestamp}
                scenarios={scenarios}
                selectedScenario={selectedScenario}
                onPlay={() => setIsPlaying(true)}
                onPause={() => setIsPlaying(false)}
                onStepForward={() => setCurrentFrame(prev => Math.min(prev + 1, totalFrames))}
                onStepBackward={() => setCurrentFrame(prev => Math.max(prev - 1, 1))}
                onReset={() => {
                  setCurrentFrame(1);
                  setIsPlaying(false);
                }}
                onSpeedChange={setSpeed}
                onFrameSeek={setCurrentFrame}
                onScenarioChange={setSelectedScenario}
              />

              <div
                style={{
                  height: '560px',
                  minHeight: '560px',
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px',
                  overflow: 'hidden',
                  background: '#060b17',
                  position: 'relative',
                }}
              >
                <CytoscapeGraph
                  elements={graphElements}
                  onNodeSelect={setSelectedNode}
                  onEdgeSelect={setSelectedEdge}
                  filterRiskThreshold={0}
                  selectedNodeType="all"
                />
              </div>
            </div>
          )}

          {/* VIEW: SCENARIO LAB */}
          {view === 'Scenario Lab' && (
            <ScenarioLabView
              onRunScenario={async (scenarioId, attackRatio) => {
                setMessage(`Simulating scenario: ${scenarioId} with ${attackRatio}% telemetry anomalies...`);
                setTimeout(() => {
                  refreshData();
                  onRefreshGraph?.();
                  setMessage(`Scenario ${scenarioId} injected and processed in analytical database.`);
                }, 1200);
              }}
            />
          )}

          {/* VIEW: EVALUATION LAB */}
          {view === 'Evaluation Lab' && <EvaluationLabView />}

          {/* VIEW: ACTIVITY LOG */}
          {view === 'Activity log' && (
            <section>
              <div className="notice">
                {apiConnected
                  ? 'Audit log synchronised with DuckDB security store.'
                  : 'Demo activity · analyst decisions in this prototype are session-only.'}
              </div>

              {(auditLogs.length > 0
                ? auditLogs
                : [
                    {
                      id: '1',
                      timestamp: '09:41',
                      event_type: 'CASE_REVIEW',
                      username: 'Janhvi S.',
                      status: 'SUCCESS',
                      details: 'Investigation CS-0042 opened: Low-and-slow activity detected for USR-028.',
                      ip_address: '127.0.0.1',
                    },
                    {
                      id: '2',
                      timestamp: '09:15',
                      event_type: 'ASSIGNMENT',
                      username: 'Janhvi S.',
                      status: 'SUCCESS',
                      details: 'CS-0041 assigned for investigation: A security analyst started reviewing evidence.',
                      ip_address: '127.0.0.1',
                    },
                    {
                      id: '3',
                      timestamp: '09:00',
                      event_type: 'BATCH_INGEST',
                      username: 'system',
                      status: 'SUCCESS',
                      details: 'Metadata batch processed: 80 pseudonymised users · 4 peer groups · no payload content.',
                      ip_address: '127.0.0.1',
                    },
                    {
                      id: '4',
                      timestamp: '08:45',
                      event_type: 'BASELINE_CHECK',
                      username: 'system',
                      status: 'SUCCESS',
                      details: 'Baseline validation completed: Trailing-window baselines checked for drift.',
                      ip_address: '127.0.0.1',
                    },
                    {
                      id: '5',
                      timestamp: '08:30',
                      event_type: 'PRIVACY_VERIFY',
                      username: 'system',
                      status: 'SUCCESS',
                      details: 'Privacy checks passed: Payload-free column whitelist verified.',
                      ip_address: '127.0.0.1',
                    },
                  ]
              ).map(item => (
                <div className="audit-row" key={item.id}>
                  <span className="audit-icon">
                    {item.event_type === 'CASE_REVIEW' ? (
                      <Shield size={16} />
                    ) : item.event_type === 'USER_CREATE' ? (
                      <FileCheck2 size={16} />
                    ) : (
                      <Activity size={16} />
                    )}
                  </span>
                  <div>
                    <h2>{item.event_type} · {item.username}</h2>
                    <p className="panel-subtitle">{item.details}</p>
                  </div>
                  <span className="audit-time">{item.timestamp}</span>
                </div>
              ))}
            </section>
          )}

          {/* VIEW: PRIVACY & CONTROLS */}
          {view === 'Privacy & controls' && (
            <section>
              <div className="notice">
                Design commitments from the CipherSentinel security specification. Operational privacy enforced at ingestion.
              </div>
              {[
                {
                  icon: EyeOff,
                  title: 'Content stays private',
                  text: 'Only network metadata is used. No message bodies, file contents, or decrypted payloads.',
                },
                {
                  icon: Fingerprint,
                  title: 'Pseudonymised identities',
                  text: 'Case evidence uses user and device aliases. Identity mapping belongs in a separate protected store.',
                },
                {
                  icon: Users,
                  title: 'Human review, always',
                  text: 'Analysts confirm or dismiss cases. A risk index is a priority signal, not a probability of wrongdoing.',
                },
                {
                  icon: LockKeyhole,
                  title: 'Two-step identity reveal',
                  text: 'Identity disclosure requires a documented reason and independent approval.',
                },
                {
                  icon: FileCheck2,
                  title: 'Auditable decisions',
                  text: 'Every review and disclosure is recorded with an actor, timestamp, and audit trail in DuckDB.',
                },
              ].map(item => (
                <div className="privacy-section" key={item.title}>
                  <item.icon size={24} />
                  <div>
                    <h2>{item.title}</h2>
                    <p className="detail-summary mt-2">{item.text}</p>
                  </div>
                  <span className="severity low">Enforced control</span>
                </div>
              ))}
            </section>
          )}

          <footer className="page-footer">
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={12} />
              Behaviour, not content. People, not probabilities.
            </span>
            <span>CipherSentinel SOC Platform · Live Backend Integration</span>
          </footer>
        </div>
      </main>

      {/* Case Review Detail Dialog */}
      <Dialog
        open={selectedCase !== null}
        onOpenChange={open => {
          if (!open) setSelectedCase(null);
        }}
      >
        <DialogContent className="detail-dialog">
          {selectedCase && (
            <>
              <div className="flex items-center gap-3">
                <span className="case-ref">{selectedCase.id} · EVIDENCE BUNDLE</span>
                <span className={`severity ${selectedCase.severity}`}>{selectedCase.severity} priority</span>
              </div>
              <DialogTitle>{selectedCase.title}</DialogTitle>
              <DialogDescription>
                {selectedCase.user} · {selectedCase.team} · {selectedCase.destination}
              </DialogDescription>
              <p className="detail-summary">
                {selectedCase.user} uploaded {selectedCase.bytes} to {selectedCase.destination} over {selectedCase.days} days.
                The {selectedCase.pattern.toLowerCase()} pattern differs from trailing baseline activity and peer groups.
              </p>

              <div className="evidence-grid">
                <div>
                  <label>Risk index</label>
                  <strong className="danger">{selectedCase.risk} / 100</strong>
                </div>
                <div>
                  <label>Confidence</label>
                  <strong>{selectedCase.confidence}%</strong>
                </div>
                <div>
                  <label>Current status</label>
                  <strong>{selectedCase.status}</strong>
                </div>
              </div>

              <h2>Evidence to review</h2>
              <ul className="evidence-list">
                <li>
                  <Check size={15} />
                  <span>Destination is uncommon within the {selectedCase.team.toLowerCase()} peer group.</span>
                </li>
                <li>
                  <Check size={15} />
                  <span>Upload activity diverges from trailing-window baseline volume.</span>
                </li>
                <li>
                  <EyeOff size={15} />
                  <span>Content and payload are never inspected. Decisions stay in human analyst hands.</span>
                </li>
              </ul>

              <RelatedFlows
                record={selectedCase}
                flows={flowStream.flows}
                onSelect={flow => {
                  setSelectedCase(null);
                  setSelectedFlow(flow);
                }}
              />

              <label className="text-xs font-medium" htmlFor="review-note">
                Analyst review note
              </label>
              <textarea
                id="review-note"
                className="review-note"
                rows={3}
                placeholder="Record operational context or mitigation reason for your decision..."
                value={note}
                onChange={e => setNote(e.target.value)}
              />

              <div className="flex items-center justify-between gap-3 mt-4">
                <Button variant="ghost" size="sm" onClick={() => downloadEvidence([selectedCase], selectedCase.id)}>
                  <Download size={13} />
                  Export evidence
                </Button>
                <div className="detail-actions">
                  <Button variant="outline" size="sm" onClick={() => handleDecide('Dismissed')}>
                    Dismiss
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => handleDecide('Investigating')}>
                    Investigate
                  </Button>
                  <Button size="sm" onClick={() => handleDecide('Confirmed')}>
                    Confirm Threat
                  </Button>
                </div>
              </div>
              <p className="text-[10px] text-muted-foreground mt-2">
                Decisions are persisted directly to DuckDB analytical database and recorded in the audit trail.
              </p>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Info / Notification Modal */}
      <Dialog
        open={info !== null}
        onOpenChange={open => {
          if (!open) setInfo(null);
        }}
      >
        <DialogContent>
          <DialogTitle>{info === 'notifications' ? 'Notifications' : 'About CipherSentinel'}</DialogTitle>
          <DialogDescription>
            {info === 'notifications'
              ? `You have ${openCount} open threat investigation cases awaiting review in this workspace.`
              : 'CipherSentinel investigates behavioural insider threat signals in encrypted network traffic without payload inspection. Integrated with FastAPI and DuckDB analytical storage.'}
          </DialogDescription>
          {info === 'notifications' && (
            <Button
              className="mt-3 cursor-pointer"
              onClick={() => {
                setInfo(null);
                setSelectedCase(cases[0] ?? null);
              }}
            >
              Review High Priority Case
              <ArrowRight size={13} />
            </Button>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};
