import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Play,
  Sliders,
  AlertTriangle,
  BarChart3,
  Compass,
  Database,
  RefreshCw,
  Server,
  Zap,
  Layers,
  ChevronRight,
  Sparkles,
} from 'lucide-react';

import { CytoscapeGraph } from './components/CytoscapeGraph';
import { InvestigationDrawer } from './components/InvestigationDrawer';
import { ReplayController } from './components/ReplayController';
import { ScenarioLabView } from './components/ScenarioLabView';
import { ThreatCasesView } from './components/ThreatCasesView';
import { EvaluationLabView } from './components/EvaluationLabView';
import { ThreatHuntingView } from './components/ThreatHuntingView';

// Default mock elements when backend is spinning up or offline
const DEFAULT_FALLBACK_ELEMENTS = {
  nodes: [
    { data: { id: 'usr-analyst-01', label: 'E049 (Fin Analyst)', type: 'user', riskScore: 84.5, totalBytes: 850000000, assetTier: 3, firstSeen: '2026-10-14 08:00', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'usr-engineer-02', label: 'E102 (DevOps Lead)', type: 'user', riskScore: 18.2, totalBytes: 34000000, assetTier: 2, firstSeen: '2026-10-14 09:30', lastSeen: '2026-10-15 11:00' } },
    { data: { id: 'usr-hr-03', label: 'E012 (HR Specialist)', type: 'user', riskScore: 12.0, totalBytes: 12000000, assetTier: 1, firstSeen: '2026-10-14 08:45', lastSeen: '2026-10-15 17:00' } },
    { data: { id: 'srv-dc-01', label: 'dc01.corp.internal', type: 'internal_server', riskScore: 45.0, totalBytes: 920000000, assetTier: 3, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 12:00' } },
    { data: { id: 'srv-dns-01', label: 'dns01.resolver.local', type: 'dns_resolver', riskScore: 15.0, totalBytes: 15000000, assetTier: 2, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 12:00' } },
    { data: { id: 'ext-s3-exfil', label: 'backup-sync.storage.example.net', type: 'cloud_saas', riskScore: 92.0, totalBytes: 820000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-15 02:30', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'ext-github', label: 'api.github.com', type: 'cloud_saas', riskScore: 5.0, totalBytes: 25000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 11:30' } },
    { data: { id: 'ext-workday', label: 'workday.saas.corp', type: 'cloud_saas', riskScore: 8.0, totalBytes: 9000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 16:45' } },
  ],
  edges: [
    { data: { id: 'flow-e1', source: 'usr-analyst-01', target: 'ext-s3-exfil', flowsCount: 42, totalBytes: 820000000, riskScore: 92.0, protocol: 'QUIC/TLS', app: 'Cloud Storage', firstSeen: '2026-10-15 02:30', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'flow-e2', source: 'usr-analyst-01', target: 'srv-dc-01', flowsCount: 15, totalBytes: 45000000, riskScore: 68.0, protocol: 'Kerberos/SMB', app: 'Active Directory', firstSeen: '2026-10-15 01:45', lastSeen: '2026-10-15 02:15' } },
    { data: { id: 'flow-e3', source: 'usr-engineer-02', target: 'ext-github', flowsCount: 120, totalBytes: 25000000, riskScore: 8.0, protocol: 'HTTPS', app: 'Code Repository', firstSeen: '2026-10-14 09:30', lastSeen: '2026-10-15 11:00' } },
    { data: { id: 'flow-e4', source: 'usr-hr-03', target: 'ext-workday', flowsCount: 88, totalBytes: 9000000, riskScore: 5.0, protocol: 'HTTPS', app: 'HR Portal', firstSeen: '2026-10-14 08:45', lastSeen: '2026-10-15 17:00' } },
    { data: { id: 'flow-e5', source: 'usr-analyst-01', target: 'srv-dns-01', flowsCount: 310, totalBytes: 1500000, riskScore: 55.0, protocol: 'DNS', app: 'Domain Resolution', firstSeen: '2026-10-15 01:30', lastSeen: '2026-10-15 03:00' } },
  ],
};

type ActiveTab = 'graph' | 'replay' | 'scenario_lab' | 'cases' | 'evaluation' | 'threat_hunting';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('graph');
  const [elements, setElements] = useState(DEFAULT_FALLBACK_ELEMENTS);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [apiConnected, setApiConnected] = useState<boolean>(false);

  // Replay State
  const [currentFrame, setCurrentFrame] = useState(5);
  const [totalFrames, setTotalFrames] = useState(12);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [currentTimestamp, setCurrentTimestamp] = useState('2026-10-15 03:15:00 UTC');
  const [scenarios, setScenarios] = useState<string[]>(['ALL_SCENARIOS', 'high_volume_exfiltration', 'low_and_slow', 'approved_backup', 'dns_entropy']);
  const [selectedScenario, setSelectedScenario] = useState('ALL_SCENARIOS');

  // Fetch live elements from backend
  const fetchGraphElements = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/graph/elements');
      if (res.ok) {
        const data = await res.json();
        if (data.nodes && data.nodes.length > 0) {
          setElements(data);
          setApiConnected(true);
        }
      } else {
        // Fallback check
        const directRes = await fetch('http://127.0.0.1:8000/graph/elements');
        if (directRes.ok) {
          const directData = await directRes.json();
          if (directData.nodes && directData.nodes.length > 0) {
            setElements(directData);
            setApiConnected(true);
          }
        }
      }
    } catch {
      // Backend may be offline or during synthetic generation; keep fallbacks
      setApiConnected(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphElements();
  }, []);

  // Replay ticker effect
  useEffect(() => {
    let interval: any = null;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentFrame((prev) => {
          if (prev >= totalFrames) {
            setIsPlaying(false);
            return prev;
          }
          const next = prev + 1;
          const hours = String(next).padStart(2, '0');
          setCurrentTimestamp(`2026-10-15 ${hours}:30:00 UTC`);
          return next;
        });
      }, 1500 / speed);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isPlaying, totalFrames, speed]);

  const handleNodeSelect = (node: any) => {
    setSelectedNode(node);
    setSelectedEdge(null);
  };

  const handleEdgeSelect = (edge: any) => {
    setSelectedEdge(edge);
    setSelectedNode(null);
  };

  const handleClearSelection = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-primary)',
        color: 'var(--text-primary)',
        overflow: 'hidden',
      }}
    >
      {/* Top SOC Navigation Header */}
      <header
        style={{
          height: 56,
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          zIndex: 40,
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              background: 'linear-gradient(135deg, #0d9488 0%, #2563eb 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 12px rgba(13, 148, 136, 0.4)',
            }}
          >
            <Shield size={18} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '0.04em', color: '#f8fafc' }}>
                CIPHERSENTINEL
              </span>
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  padding: '2px 6px',
                  borderRadius: 4,
                  background: 'rgba(13, 148, 136, 0.2)',
                  color: 'var(--accent-teal)',
                  border: '1px solid rgba(13, 148, 136, 0.3)',
                }}
              >
                GRAPH SIMULATOR
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Temporal Insider Threat Detection & SOC Analysis Platform
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <nav style={{ display: 'flex', gap: 4, background: 'var(--bg-surface)', padding: 4, borderRadius: 8, border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveTab('graph')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'graph' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'graph' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Layers size={14} /> Network Graph
          </button>

          <button
            onClick={() => setActiveTab('replay')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'replay' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'replay' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Play size={14} /> Temporal Replay
          </button>

          <button
            onClick={() => setActiveTab('scenario_lab')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'scenario_lab' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'scenario_lab' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Sliders size={14} /> What-If Scenario Lab
          </button>

          <button
            onClick={() => setActiveTab('cases')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'cases' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'cases' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <AlertTriangle size={14} /> Threat Cases
          </button>

          <button
            onClick={() => setActiveTab('evaluation')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'evaluation' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'evaluation' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <BarChart3 size={14} /> Evaluation Lab
          </button>

          <button
            onClick={() => setActiveTab('threat_hunting')}
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeTab === 'threat_hunting' ? 'var(--accent-teal)' : 'transparent',
              color: activeTab === 'threat_hunting' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Compass size={14} /> Threat Hunting
          </button>
        </nav>

        {/* Status Indicators & External Link */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: apiConnected ? 'var(--accent-teal)' : '#f59e0b',
                boxShadow: apiConnected ? '0 0 8px var(--accent-teal)' : 'none',
              }}
            />
            <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
              {apiConnected ? 'FastAPI 8000 Connected' : 'Demo Dataset Mode'}
            </span>
          </div>

          <a
            href="http://localhost:8501"
            target="_blank"
            rel="noreferrer"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              borderRadius: 6,
              background: 'rgba(59, 130, 246, 0.15)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              color: '#60a5fa',
              fontSize: 12,
              fontWeight: 500,
              textDecoration: 'none',
            }}
          >
            Streamlit SOC <ChevronRight size={13} />
          </a>
        </div>
      </header>

      {/* Main View Body */}
      <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
        {(activeTab === 'graph' || activeTab === 'replay') && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', position: 'relative' }}>
            {/* Cytoscape Graph Area */}
            <div style={{ flex: 1, position: 'relative' }}>
              <CytoscapeGraph
                elements={elements}
                onSelectNode={handleNodeSelect}
                onSelectEdge={handleEdgeSelect}
                onClearSelection={handleClearSelection}
                isLoading={loading}
              />
            </div>

            {/* Replay Controller Toolbar at bottom */}
            {activeTab === 'replay' && (
              <ReplayController
                currentFrame={currentFrame}
                totalFrames={totalFrames}
                isPlaying={isPlaying}
                speed={speed}
                currentTimestamp={currentTimestamp}
                onPlayToggle={() => setIsPlaying(!isPlaying)}
                onReset={() => {
                  setIsPlaying(false);
                  setCurrentFrame(1);
                  setCurrentTimestamp('2026-10-15 01:00:00 UTC');
                }}
                onStepForward={() => setCurrentFrame((f) => Math.min(totalFrames, f + 1))}
                onStepBackward={() => setCurrentFrame((f) => Math.max(1, f - 1))}
                onSeek={(frame) => setCurrentFrame(frame)}
                onSpeedChange={(s) => setSpeed(s)}
                scenarios={scenarios}
                selectedScenario={selectedScenario}
                onScenarioChange={(s) => setSelectedScenario(s)}
              />
            )}
          </div>
        )}

        {/* Investigation Drawer when node or edge is selected */}
        {(activeTab === 'graph' || activeTab === 'replay') && (
          <InvestigationDrawer
            selectedNode={selectedNode}
            selectedEdge={selectedEdge}
            onClose={handleClearSelection}
          />
        )}

        {/* Tab Views */}
        {activeTab === 'scenario_lab' && (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <ScenarioLabView />
          </div>
        )}

        {activeTab === 'cases' && (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <ThreatCasesView />
          </div>
        )}

        {activeTab === 'evaluation' && (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <EvaluationLabView />
          </div>
        )}

        {activeTab === 'threat_hunting' && (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <ThreatHuntingView />
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
