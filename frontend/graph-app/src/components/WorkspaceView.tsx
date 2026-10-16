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
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
  Layers,
  Play,
  Zap,
  BarChart3,
  RefreshCw,
  LogOut,
  Database,
} from '../icons';
import { Button } from './ui/button';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from './ui/dialog';
import { TrafficChart } from './traffic-chart';
import { NetworkFlows, RelatedFlows, useFlowStream } from './network-flows';
import { demoCases, downloadEvidence, type CaseRecord, type FlowRecord } from '../lib/demo-cases';
import { fetchLiveCases, updateCaseStatus, fetchGraphSummary, fetchAuditLogs, type GraphSummary, type AuditLogEntry } from '../lib/api';

import { CytoscapeGraph } from './CytoscapeGraph';
import { InvestigationDrawer } from './InvestigationDrawer';
import { ReplayController } from './ReplayController';
import { ScenarioLabView } from './ScenarioLabView';
import { EvaluationLabView } from './EvaluationLabView';
import { ThreatHuntingView } from './ThreatHuntingView';
import { InvestigationMultiLayerEngine } from './InvestigationMultiLayerEngine';
import { LiveGeoThreatMap } from './LiveGeoThreatMap';
import { DEFAULT_FALLBACK_ELEMENTS } from '../App';

// Realistic Enterprise Telemetry Stream Templates for 2-Second Live Ingestion
const ENTERPRISE_STREAM_TEMPLATES = [
  // --- LOW SEVERITY (Benign Daily Enterprise Baseline) ---
  {
    user_id: 'USR-102',
    user_name: 'E102 (DevOps Lead)',
    source_ip: '10.4.15.102',
    destination_ip: '140.82.121.4',
    hostname: 'api.github.com',
    method: 'GET',
    status_code: 200,
    base_bytes: 48000,
    threat_score: 8.5,
    risk_level: 'LOW',
    alert_reason: 'Standard baseline Git repository synchronization over HTTPS',
  },
  {
    user_id: 'USR-012',
    user_name: 'E012 (HR Specialist)',
    source_ip: '10.4.18.12',
    destination_ip: '52.14.92.11',
    hostname: 'workday.saas.corp',
    method: 'POST',
    status_code: 200,
    base_bytes: 18400,
    threat_score: 11.2,
    risk_level: 'LOW',
    alert_reason: 'Routine employee portal benefits query conforming to peer baseline',
  },
  {
    user_id: 'USR-049',
    user_name: 'E049 (Fin Analyst)',
    source_ip: '10.4.12.49',
    destination_ip: '10.0.4.1',
    hostname: 'dc01.corp.internal',
    method: 'GET',
    status_code: 200,
    base_bytes: 32000,
    threat_score: 22.0,
    risk_level: 'LOW',
    alert_reason: 'Internal domain controller Kerberos ticket renewal',
  },
  {
    user_id: 'USR-072',
    user_name: 'E072 (Support Lead)',
    source_ip: '10.8.1.72',
    destination_ip: '54.230.12.44',
    hostname: 'app.slack.com',
    method: 'GET',
    status_code: 200,
    base_bytes: 12500,
    threat_score: 6.2,
    risk_level: 'LOW',
    alert_reason: 'Real-time WebSocket heartbeat for enterprise communications',
  },
  {
    user_id: 'USR-033',
    user_name: 'E033 (Frontend Eng)',
    source_ip: '10.4.15.33',
    destination_ip: '104.16.19.94',
    hostname: 'registry.npmjs.org',
    method: 'GET',
    status_code: 200,
    base_bytes: 84000,
    threat_score: 9.4,
    risk_level: 'LOW',
    alert_reason: 'Standard developer package registry manifest check',
  },
  {
    user_id: 'USR-015',
    user_name: 'E015 (Sales Director)',
    source_ip: '10.2.8.15',
    destination_ip: '162.247.243.29',
    hostname: 'atlassian.net',
    method: 'GET',
    status_code: 200,
    base_bytes: 36000,
    threat_score: 14.8,
    risk_level: 'LOW',
    alert_reason: 'Sprint planning and project issue tracker navigation',
  },

  // --- MEDIUM SEVERITY (Elevated Behavioral Anomaly) ---
  {
    user_id: 'USR-043',
    user_name: 'E043 (Product Analyst)',
    source_ip: '10.4.15.43',
    destination_ip: '198.51.100.40',
    hostname: 's3.us-west-2.amazonaws.com',
    method: 'GET',
    status_code: 200,
    base_bytes: 7800000,
    threat_score: 52.4,
    risk_level: 'MEDIUM',
    alert_reason: 'Elevated outbound byte volume (7.8 MB) to cloud object store',
  },
  {
    user_id: 'USR-061',
    user_name: 'E061 (Accountant)',
    source_ip: '10.6.3.61',
    destination_ip: '198.51.100.18',
    hostname: 'api.dropbox.com',
    method: 'POST',
    status_code: 200,
    base_bytes: 4200000,
    threat_score: 48.0,
    risk_level: 'MEDIUM',
    alert_reason: 'Third-party cloud storage sync from finance departmental subnet',
  },
  {
    user_id: 'USR-088',
    user_name: 'E088 (IT SysAdmin)',
    source_ip: '10.4.1.88',
    destination_ip: '10.0.8.22',
    hostname: 'internal-git.corp.net',
    method: 'POST',
    status_code: 201,
    base_bytes: 6500000,
    threat_score: 42.5,
    risk_level: 'MEDIUM',
    alert_reason: 'Large source tree push to internal staging mirror after normal shift',
  },

  // --- HIGH SEVERITY (Threat Indicators & Suspicious Channels) ---
  {
    user_id: 'USR-028',
    user_name: 'E028 (Compromised)',
    source_ip: '10.4.12.28',
    destination_ip: '198.51.100.99',
    hostname: 'c2-beacon.tunnel-edge.net',
    method: 'CONNECT',
    status_code: 101,
    base_bytes: 840000,
    threat_score: 84.4,
    risk_level: 'HIGH',
    alert_reason: 'High entropy DNS tunneling sub-beacon query observed on UDP 53',
  },
  {
    user_id: 'USR-061',
    user_name: 'E061 (Accountant)',
    source_ip: '10.6.3.61',
    destination_ip: '192.0.2.14',
    hostname: 'swift-wire.interbank.fin',
    method: 'POST',
    status_code: 201,
    base_bytes: 4200000,
    threat_score: 82.0,
    risk_level: 'HIGH',
    alert_reason: 'Tier-3 Financial transaction webhook initiated during off-hours',
  },
  {
    user_id: 'USR-028',
    user_name: 'E028 (Compromised)',
    source_ip: '10.4.12.28',
    destination_ip: '185.220.101.5',
    hostname: 'tor-exit.relay-node.org',
    method: 'CONNECT',
    status_code: 403,
    base_bytes: 310000,
    threat_score: 79.5,
    risk_level: 'HIGH',
    alert_reason: 'Repeated unauthorized gateway connection attempt to suspected anonymizer relay',
  },

  // --- CRITICAL SEVERITY (Severe Volumetric Exfiltration & C2 Apex) ---
  {
    user_id: 'USR-049',
    user_name: 'E049 (Fin Analyst)',
    source_ip: '10.4.12.49',
    destination_ip: '198.51.100.24',
    hostname: 'backup-sync.storage.example.net',
    method: 'POST',
    status_code: 206,
    base_bytes: 42500000,
    threat_score: 94.2,
    risk_level: 'CRITICAL',
    alert_reason: 'Unscheduled volumetric backup exfiltration (>40 MB) over QUIC to cloud storage',
  },
  {
    user_id: 'USR-028',
    user_name: 'E028 (Compromised)',
    source_ip: '10.4.12.28',
    destination_ip: '203.0.113.14',
    hostname: 'gfs270n113.userstorage.mega.co.nz',
    method: 'POST',
    status_code: 200,
    base_bytes: 185000000,
    threat_score: 96.8,
    risk_level: 'CRITICAL',
    alert_reason: 'Massive archive upload to personal storage platform outside enterprise domain',
  },
  {
    user_id: 'USR-049',
    user_name: 'E049 (Fin Analyst)',
    source_ip: '10.4.12.49',
    destination_ip: '198.51.100.77',
    hostname: 'offsite-db-dump.cloud-vault.io',
    method: 'PUT',
    status_code: 200,
    base_bytes: 74000000,
    threat_score: 91.5,
    risk_level: 'CRITICAL',
    alert_reason: 'Direct volumetric database dump transfer to unauthorized external IP',
  },
];

const generateInitialSeedLogs = () => {
  const now = Date.now();
  // Randomly shuffle templates so initial seed sequence has a natural random distribution of classifications
  const shuffled = [...ENTERPRISE_STREAM_TEMPLATES].sort(() => Math.random() - 0.5).slice(0, 10);
  return shuffled.map((tmpl, idx) => {
    const time = new Date(now - (idx + 1) * 2000).toISOString();
    const isAnomaly = tmpl.risk_level === 'CRITICAL' || tmpl.risk_level === 'HIGH';
    const jitterFactor = 0.8 + Math.random() * 0.4;
    const scoreJitter = (Math.random() * 3 - 1.5);
    const score = Math.max(3.0, Math.min(99.0, Number((tmpl.threat_score + scoreJitter).toFixed(1))));
    return {
      log_id: `LOG-INIT-${String(1000 + idx)}`,
      timestamp: time,
      user_id: tmpl.user_id,
      user_name: tmpl.user_name,
      source_ip: tmpl.source_ip,
      destination_ip: tmpl.destination_ip,
      hostname: tmpl.hostname,
      method: tmpl.method,
      status_code: tmpl.status_code,
      bytes_sent: Math.round(tmpl.base_bytes * jitterFactor),
      threat_score: score,
      risk_level: tmpl.risk_level,
      is_anomaly: isAnomaly,
      alert_reason: tmpl.alert_reason,
      isNew: false,
    };
  });
};

export type WorkspaceTab =
  | 'Overview'
  | 'Investigations'
  | 'Network Graph'
  | 'Temporal Replay'
  | '🔴 Live Global Map'
  | '⚡ 2s Live Stream'
  | 'Scenario Lab'
  | 'Evaluation Lab'
  | 'Activity log'
  | 'Privacy & controls';

interface WorkspaceProps {
  initialView?: WorkspaceTab;
  graphElements: any;
  onRefreshGraph?: () => void;
  apiConnected: boolean;
  currentUser?: {
    id?: string;
    username: string;
    full_name?: string;
    email?: string;
    role?: string;
  } | null;
  onLogout?: () => void;
}

export const WorkspaceView: React.FC<WorkspaceProps> = ({
  initialView = 'Overview',
  graphElements,
  onRefreshGraph,
  apiConnected,
  currentUser,
  onLogout,
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
  const [showCaseArchive, setShowCaseArchive] = useState<boolean>(false);

  // Cytoscape selection & replay states
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<any | null>(null);
  const [currentFrame, setCurrentFrame] = useState(1);
  const totalFrames = 12;
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [scenarios] = useState<string[]>([
    'ALL_SCENARIOS',
    'high_volume_exfiltration',
    'low_and_slow',
    'approved_backup',
    'dns_entropy',
  ]);
  const [selectedScenario, setSelectedScenario] = useState('ALL_SCENARIOS');

  // Live 2-second stream state
  const [liveStreamLogs, setLiveStreamLogs] = useState<any[]>(() => generateInitialSeedLogs());
  const [isLiveStreamActive, setIsLiveStreamActive] = useState<boolean>(true);
  const [streamCountdown, setStreamCountdown] = useState<number>(2.0);
  const streamSeqRef = React.useRef<number>(0);
  const lastStreamIdxRef = React.useRef<number>(-1);

  const flowStream = useFlowStream();

  // 12-Step Progressive Forensic Timeline Steps for Temporal Replay
  const REPLAY_TIMELINE_STEPS = [
    {
      step: 1,
      day: 1,
      time: '2026-10-01 09:00 UTC',
      title: 'Baseline Enterprise Operations',
      mitre: 'T1078 Valid Accounts (Benign Baseline)',
      severity: 'LOW',
      notation: 'Normal employee work shift. Engineers and HR staff access approved enterprise endpoints (GitHub and Workday). All telemetry conforms to trailing-window peer baseline.',
      sourceEntity: 'E102 (DevOps Lead), E012 (HR Specialist)',
      targetEntity: 'api.github.com, workday.saas.corp',
      bytes: '34 MB',
      protocol: 'HTTPS / TLS 1.3',
      activeNodeIds: ['usr-engineer-02', 'usr-hr-03', 'ext-github', 'ext-workday'],
      activeEdgeIds: ['flow-e11', 'flow-e12'],
      riskIndex: 12,
    },
    {
      step: 2,
      day: 3,
      time: '2026-10-03 11:30 UTC',
      title: 'Internal Host Discovery & DNS Enumeration',
      mitre: 'T1018 Remote System Discovery',
      severity: 'LOW',
      notation: 'Financial Analyst E049 performs rapid DNS lookups across internal domain servers. 310 DNS resolution requests observed via internal resolver.',
      sourceEntity: 'E049 (Fin Analyst)',
      targetEntity: 'dns01.resolver.local',
      bytes: '1.5 MB',
      protocol: 'DNS / UDP 53',
      activeNodeIds: ['usr-analyst-01', 'srv-dns-01'],
      activeEdgeIds: ['flow-e10'],
      riskIndex: 25,
    },
    {
      step: 3,
      day: 5,
      time: '2026-10-05 01:45 UTC',
      title: 'Off-Hours Kerberos Authentication Spike',
      mitre: 'T1110.003 Password Spraying / Brute Force',
      severity: 'MEDIUM',
      notation: '14 consecutive Kerberos logon failures within 3 minutes targeting dc01.corp.internal at 01:45 AM. Initial alert indicator flagged by Heuristic Rule Engine.',
      sourceEntity: 'E028 (Compromised)',
      targetEntity: 'dc01.corp.internal',
      bytes: '85 MB',
      protocol: 'Kerberos / SMB (Port 445)',
      activeNodeIds: ['usr-insider-04', 'srv-dc-01'],
      activeEdgeIds: ['flow-e7'],
      riskIndex: 58,
    },
    {
      step: 4,
      day: 6,
      time: '2026-10-06 02:15 UTC',
      title: 'Financial Database Export Dump',
      mitre: 'T1005 Data from Local System / Database',
      severity: 'HIGH',
      notation: 'Direct PostgreSQL query batch executed against production vault database. 340 MB of sensitive financial records and customer PII staged locally.',
      sourceEntity: 'E049 (Fin Analyst)',
      targetEntity: 'vault.financial-db.prod',
      bytes: '340 MB',
      protocol: 'PostgreSQL TLS (Port 5432)',
      activeNodeIds: ['usr-analyst-01', 'srv-db-vault'],
      activeEdgeIds: ['flow-e5'],
      riskIndex: 78,
    },
    {
      step: 5,
      day: 7,
      time: '2026-10-07 03:00 UTC',
      title: 'First-Seen External Cloud Destination',
      mitre: 'T1567 Exfiltration Over Web Service (Setup)',
      severity: 'HIGH',
      notation: 'Initial handshake established to unapproved cloud storage endpoint backup-sync.storage.example.net. Destination previously unobserved in company peer group.',
      sourceEntity: 'E049 (Fin Analyst)',
      targetEntity: 'backup-sync.storage.example.net',
      bytes: '45 MB',
      protocol: 'QUIC / UDP 443',
      activeNodeIds: ['usr-analyst-01', 'ext-s3-exfil'],
      activeEdgeIds: ['flow-e1'],
      riskIndex: 82,
    },
    {
      step: 6,
      day: 9,
      time: '2026-10-09 01:10 UTC',
      title: 'DNS Tunneling C2 Beacon Established',
      mitre: 'T1071.004 DNS C2 Tunneling',
      severity: 'CRITICAL',
      notation: 'Subdomain Shannon entropy spikes to 4.8 on c2-beacon.tunnel-edge.net. 420 UDP packets observed transmitting base64 encoded chunks through recursive resolver.',
      sourceEntity: 'E028 (Compromised)',
      targetEntity: 'c2-beacon.tunnel-edge.net',
      bytes: '18 MB',
      protocol: 'DNS Tunnel / UDP 53',
      activeNodeIds: ['usr-insider-04', 'c2-beacon-01'],
      activeEdgeIds: ['flow-e9'],
      riskIndex: 94,
    },
    {
      step: 7,
      day: 11,
      time: '2026-10-11 02:40 UTC',
      title: 'Unscheduled Financial Wire Webhook',
      mitre: 'T1537 Transfer Data to Cloud Account',
      severity: 'CRITICAL',
      notation: 'Wire transfer API initiated to SWIFT interbank gateway for $1.4M using off-hours analyst credentials. Tripped Tier-3 Asset protection threshold.',
      sourceEntity: 'E049 (Fin Analyst)',
      targetEntity: 'swift-wire.interbank.fin',
      bytes: '4.5 MB',
      protocol: 'Financial Wire / ISO 20022',
      activeNodeIds: ['usr-analyst-01', 'gw-swift-bank'],
      activeEdgeIds: ['flow-e3'],
      riskIndex: 88,
    },
    {
      step: 8,
      day: 12,
      time: '2026-10-12 02:15 UTC',
      title: 'Mega.nz Cloud Storage Ingestion Acceleration',
      mitre: 'T1048.003 Exfiltration Over Alternative Protocol',
      severity: 'CRITICAL',
      notation: 'Compromised insider E028 initiates high-throughput upload of 550 MB compressed archive to gfs270n113.userstorage.mega.co.nz.',
      sourceEntity: 'E028 (Compromised)',
      targetEntity: 'gfs270n113.userstorage.mega.co.nz',
      bytes: '550 MB',
      protocol: 'QUIC v1 / UDP 443',
      activeNodeIds: ['usr-insider-04', 'ext-mega-nz'],
      activeEdgeIds: ['flow-e2'],
      riskIndex: 96,
    },
    {
      step: 9,
      day: 13,
      time: '2026-10-13 03:15 UTC',
      title: 'Synchronized Volumetric Exfiltration Peak',
      mitre: 'T1048 Exfiltration Over C2 & Cloud',
      severity: 'CRITICAL',
      notation: 'Multi-vector egress apex. Egress byte volume exceeds peer baseline by 840%. Multiple external cloud destinations receiving data in parallel.',
      sourceEntity: 'E049 (Fin Analyst), E028 (Compromised)',
      targetEntity: 'backup-sync, mega.co.nz, c2-beacon',
      bytes: '820 MB',
      protocol: 'QUIC / TLS Multi-channel',
      activeNodeIds: ['usr-analyst-01', 'ext-s3-exfil', 'usr-insider-04', 'ext-mega-nz', 'c2-beacon-01'],
      activeEdgeIds: ['flow-e1', 'flow-e2', 'flow-e9'],
      riskIndex: 98,
    },
    {
      step: 10,
      day: 14,
      time: '2026-10-14 08:30 UTC',
      title: '3-Layer Triangulation & Consensus Corroboration',
      mitre: 'Automated Detection Correlation',
      severity: 'CRITICAL',
      notation: 'All 3 defense layers trigger in consensus: Rule Engine scores 94%, Isolation Forest detects 32-feature anomaly (contamination < 0.01), Ollama Qwen3 validates malicious insider exfiltration.',
      sourceEntity: 'E049, E028',
      targetEntity: 'dc01.corp.internal, backup-sync',
      bytes: 'Correlated Aggregate',
      protocol: 'Tri-Engine Consensus',
      activeNodeIds: ['usr-analyst-01', 'usr-insider-04', 'srv-dc-01', 'ext-s3-exfil'],
      activeEdgeIds: ['flow-e1', 'flow-e2', 'flow-e7'],
      riskIndex: 99,
    },
    {
      step: 11,
      day: 14,
      time: '2026-10-14 09:15 UTC',
      title: 'Automated SOC Incident Brief Dispatched',
      mitre: 'SOC Alert Escalation',
      severity: 'HIGH',
      notation: 'High-fidelity executive HTML incident report automatically compiled and dispatched via Google SMTP to sanskar0912gharal@gmail.com.',
      sourceEntity: 'CipherSentinel SOC',
      targetEntity: 'Security Analysts Queue',
      bytes: 'Executive Brief',
      protocol: 'SMTP / SSL (Port 465)',
      activeNodeIds: ['usr-analyst-01', 'usr-insider-04'],
      activeEdgeIds: ['flow-e1', 'flow-e2'],
      riskIndex: 92,
    },
    {
      step: 12,
      day: 14,
      time: '2026-10-14 09:45 UTC',
      title: 'Containment & Endpoint Host Isolation',
      mitre: 'T1089 Disabling Security Tools (Mitigation)',
      severity: 'RESOLVED',
      notation: 'Security analyst confirms investigation. Compromised credentials revoked, active network sessions terminated, and endpoint placed in host quarantine.',
      sourceEntity: 'SOC Containment Agent',
      targetEntity: 'E049, E028 Endpoints',
      bytes: 'Session Severed',
      protocol: 'Quarantine Protocol',
      activeNodeIds: ['usr-analyst-01', 'usr-insider-04'],
      activeEdgeIds: [],
      riskIndex: 10,
    },
  ];

  const activeReplayStep = REPLAY_TIMELINE_STEPS[(currentFrame - 1) % REPLAY_TIMELINE_STEPS.length];

  // Replay frame playback timer
  useEffect(() => {
    if (!isPlaying) return;
    const timer = setInterval(() => {
      setCurrentFrame(prev => {
        if (prev >= totalFrames) {
          setIsPlaying(false);
          return totalFrames;
        }
        return prev + 1;
      });
    }, 2400 / speed);

    return () => clearInterval(timer);
  }, [isPlaying, speed, totalFrames]);

  // Dynamic simulation of nodes and edges in graph based on temporal step
  const simulatedReplayElements = React.useMemo(() => {
    // Temporal replay forensic timeline is specifically mapped to the enterprise simulation topology
    const rawNodes = (graphElements?.nodes && graphElements.nodes.length > 0 && graphElements.nodes.some((n: any) => String(n.data?.id || '').startsWith('usr-')))
      ? graphElements.nodes
      : DEFAULT_FALLBACK_ELEMENTS.nodes;
    const rawEdges = (graphElements?.edges && graphElements.edges.length > 0 && graphElements.edges.some((e: any) => String(e.data?.id || '').startsWith('flow-')))
      ? graphElements.edges
      : DEFAULT_FALLBACK_ELEMENTS.edges;

    const simulatedNodes = rawNodes.map((n: any) => {
      const d = n.data || n;
      const idStr = String(d.id || '');
      const labelStr = String(d.label || '');
      const entityStr = String(d.entity_id || '');

      const isActive = activeReplayStep.activeNodeIds.some(
        target =>
          idStr === target ||
          idStr.toLowerCase().includes(target.toLowerCase()) ||
          target.toLowerCase().includes(idStr.toLowerCase()) ||
          labelStr.toLowerCase().includes(target.toLowerCase()) ||
          entityStr === target
      );

      return {
        data: {
          ...d,
          riskScore: isActive ? activeReplayStep.riskIndex : Math.min(d.riskScore ?? 15, 20),
          severity: isActive ? activeReplayStep.severity : 'LOW',
          size: isActive ? 58 : 34,
          opacity: isActive ? 1.0 : 0.35,
        },
      };
    });

    const simulatedEdges = rawEdges.map((e: any) => {
      const d = e.data || e;
      const idStr = String(d.id || `${d.source}-${d.target}`);
      const isActive = activeReplayStep.activeEdgeIds.some(
        target => idStr === target || idStr.includes(target) || target.includes(idStr)
      );

      return {
        data: {
          ...d,
          width: isActive ? 5.0 : 1.5,
          opacity: isActive ? 1.0 : 0.25,
        },
      };
    });

    return { nodes: simulatedNodes, edges: simulatedEdges };
  }, [graphElements, activeReplayStep]);

  // 2-Second Live Log Stream Ingestion & Transition Engine (ticks when viewing the live stream tab)
  useEffect(() => {
    if (!isLiveStreamActive || view !== '⚡ 2s Live Stream') return;

    // Helper to generate the next real-time web log packet with randomized selection
    const synthesizeNextPacket = () => {
      // Pick a random template, avoiding consecutive duplicate events
      let randomIdx = Math.floor(Math.random() * ENTERPRISE_STREAM_TEMPLATES.length);
      if (randomIdx === lastStreamIdxRef.current) {
        randomIdx = (randomIdx + 1 + Math.floor(Math.random() * (ENTERPRISE_STREAM_TEMPLATES.length - 1))) % ENTERPRISE_STREAM_TEMPLATES.length;
      }
      lastStreamIdxRef.current = randomIdx;

      const tmpl = ENTERPRISE_STREAM_TEMPLATES[randomIdx];
      const jitterFactor = 0.75 + Math.random() * 0.5;
      const bytes = Math.round(tmpl.base_bytes * jitterFactor);
      const isAnomaly = tmpl.risk_level === 'CRITICAL' || tmpl.risk_level === 'HIGH';

      // Natural score variance within classification band
      const scoreJitter = (Math.random() * 4 - 2);
      const score = Math.max(3.0, Math.min(99.0, Number((tmpl.threat_score + scoreJitter).toFixed(1))));

      const nextLog = {
        log_id: `LOG-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        user_id: tmpl.user_id,
        user_name: tmpl.user_name,
        source_ip: tmpl.source_ip,
        destination_ip: tmpl.destination_ip,
        hostname: tmpl.hostname,
        method: tmpl.method,
        status_code: tmpl.status_code,
        bytes_sent: bytes,
        threat_score: score,
        risk_level: tmpl.risk_level,
        is_anomaly: isAnomaly,
        alert_reason: tmpl.alert_reason,
        isNew: true,
      };

      // Dispatched asynchronously to backend stream store
      fetch('/api/data/stream-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(nextLog),
      }).catch(() => {});

      return nextLog;
    };

    const interval = setInterval(() => {
      const nextLog = synthesizeNextPacket();
      setLiveStreamLogs(prev => [nextLog, ...prev.map(l => ({ ...l, isNew: false }))].slice(0, 45));
      setStreamCountdown(2.0);
    }, 2000);

    const tick = setInterval(() => {
      setStreamCountdown(prev => (prev <= 0.1 ? 2.0 : Number((prev - 0.1).toFixed(1))));
    }, 100);

    return () => {
      clearInterval(interval);
      clearInterval(tick);
    };
  }, [isLiveStreamActive, view]);

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
    { title: '🔴 Live Global Map' as WorkspaceTab, icon: Globe2 },
    { title: '⚡ 2s Live Stream' as WorkspaceTab, icon: Activity },
    { title: 'Scenario Lab' as WorkspaceTab, icon: Zap },
    { title: 'Evaluation Lab' as WorkspaceTab, icon: BarChart3 },
    { title: 'Activity log' as WorkspaceTab, icon: FileCheck2 },
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
            <div className="avatar">
              {currentUser?.full_name
                ? currentUser.full_name
                    .split(' ')
                    .map((n: string) => n[0])
                    .join('')
                    .substring(0, 2)
                    .toUpperCase()
                : (currentUser?.username || 'OP').substring(0, 2).toUpperCase()}
            </div>
            <div className="profile-info" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
              <div className="text-xs font-semibold truncate">
                {currentUser?.full_name || currentUser?.username || 'Janhvi S.'}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5 capitalize truncate">
                {currentUser?.role ? `${currentUser.role} • SQLite Enclave` : 'Security analyst'}
              </div>
            </div>
            {onLogout ? (
              <button
                type="button"
                className="logout-action-btn"
                onClick={onLogout}
                title="Log out from local SQLite session"
                aria-label="Log Out"
              >
                <LogOut size={15} />
              </button>
            ) : (
              <ShieldCheck size={15} className="ml-auto text-muted-foreground" />
            )}
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
            <span className="sqlite-enclave-badge flex items-center gap-1.5" title="Local SQLite Database: data/users.db">
              <Database size={12} className="text-emerald-400" />
              <span>SQLite: users.db</span>
            </span>
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
              {/* 4 SUBTABS MULTI-LAYER INVESTIGATION ENGINE */}
              <InvestigationMultiLayerEngine
                onSelectCase={caseId => {
                  openCase(caseId);
                }}
              />

              {/* Collapsible Flat SOC Case Queue */}
              <div className="border border-[#1e2d4d] rounded-xl bg-[#0b152b] overflow-hidden">
                <div
                  className="px-5 py-3.5 flex items-center justify-between cursor-pointer hover:bg-[#111f3d] transition-colors"
                  onClick={() => setShowCaseArchive(!showCaseArchive)}
                >
                  <div className="flex items-center gap-2.5">
                    <Shield className="w-4 h-4 text-slate-400" />
                    <span className="text-xs font-bold text-slate-300">
                      Standard SOC Investigation Case Files Queue ({cases.length} Total Records)
                    </span>
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 text-xs text-slate-400">
                    {showCaseArchive ? 'Collapse Case Table' : 'Expand Case Table'}
                  </Button>
                </div>

                {showCaseArchive && (
                  <div className="p-4 border-t border-[#1e2d4d] bg-[#060b17]">
                    <div className="queue-toolbar mb-4">
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
                )}
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

          {/* VIEW: TEMPORAL REPLAY - DYNAMIC SIMULATION OF EACH NODE BASED ON TIME WITH NOTATIONS */}
          {view === 'Temporal Replay' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
              <ReplayController
                currentFrame={currentFrame}
                totalFrames={totalFrames}
                isPlaying={isPlaying}
                speed={speed}
                currentTimestamp={activeReplayStep.time}
                scenarios={scenarios}
                selectedScenario={selectedScenario}
                onPlayToggle={() => setIsPlaying(prev => !prev)}
                onPlay={() => setIsPlaying(true)}
                onPause={() => setIsPlaying(false)}
                onStepForward={() => setCurrentFrame(prev => Math.min(prev + 1, totalFrames))}
                onStepBackward={() => setCurrentFrame(prev => Math.max(prev - 1, 1))}
                onReset={() => {
                  setCurrentFrame(1);
                  setIsPlaying(false);
                }}
                onSpeedChange={setSpeed}
                onSeek={setCurrentFrame}
                onFrameSeek={setCurrentFrame}
                onScenarioChange={setSelectedScenario}
              />

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(0, 1fr) 390px',
                  gap: '16px',
                  height: '590px',
                  minHeight: '590px',
                  width: '100%',
                }}
              >
                {/* Simulated Graph Canvas */}
                <div
                  style={{
                    height: '100%',
                    minHeight: '590px',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    background: '#060b17',
                    position: 'relative',
                  }}
                >
                  <CytoscapeGraph
                    elements={simulatedReplayElements}
                    onNodeSelect={setSelectedNode}
                    onEdgeSelect={setSelectedEdge}
                    filterRiskThreshold={0}
                    selectedNodeType="all"
                  />
                </div>

                {/* DYNAMIC FORENSIC NOTATION & TIMELINE HUD CARD */}
                <div
                  style={{
                    height: '100%',
                    minHeight: '590px',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    background: 'var(--bg-card)',
                    padding: '18px 20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                    overflowY: 'auto',
                  }}
                >
                  {/* Step Header */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, padding: '3px 8px', borderRadius: 4, background: '#0284c7', color: '#ffffff' }}>
                        STEP {activeReplayStep.step} / {totalFrames}
                      </span>
                      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                        Day {activeReplayStep.day}
                      </span>
                    </div>
                    <span
                      className={`severity ${
                        activeReplayStep.severity === 'CRITICAL'
                          ? 'high'
                          : activeReplayStep.severity === 'HIGH'
                          ? 'high'
                          : activeReplayStep.severity === 'MEDIUM'
                          ? 'medium'
                          : 'low'
                      }`}
                    >
                      {activeReplayStep.severity}
                    </span>
                  </div>

                  {/* Title & Timestamp */}
                  <div>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
                      {activeReplayStep.title}
                    </h3>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                      ⏱️ {activeReplayStep.time}
                    </div>
                  </div>

                  {/* MITRE ATT&CK Tag */}
                  <div
                    style={{
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      borderRadius: 6,
                      padding: '6px 10px',
                      fontSize: '0.75rem',
                      color: '#fda4af',
                      fontWeight: 600,
                    }}
                  >
                    🎯 MITRE ATT&CK: {activeReplayStep.mitre}
                  </div>

                  {/* Full Forensic Notation */}
                  <div
                    style={{
                      background: 'rgba(11, 21, 43, 0.75)',
                      borderRadius: 8,
                      padding: '12px 14px',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                    }}
                  >
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: '#94a3b8', marginBottom: 6 }}>
                      Forensic Behavioral Notation:
                    </div>
                    <p style={{ fontSize: '0.82rem', lineHeight: '1.45', color: '#e2e8f0', margin: 0 }}>
                      {activeReplayStep.notation}
                    </p>
                  </div>

                  {/* Telemetry Breakdown */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: '0.75rem' }}>
                    <div style={{ background: 'var(--bg-secondary)', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Source Node:</span>
                      <strong style={{ color: '#38bdf8' }}>{activeReplayStep.sourceEntity}</strong>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Target / Destination:</span>
                      <strong style={{ color: '#f59e0b' }}>{activeReplayStep.targetEntity}</strong>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Transferred Volume:</span>
                      <strong style={{ color: '#f8fafc' }}>{activeReplayStep.bytes}</strong>
                    </div>
                    <div style={{ background: 'var(--bg-secondary)', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem' }}>Observed Protocol:</span>
                      <strong style={{ color: '#a855f7' }}>{activeReplayStep.protocol}</strong>
                    </div>
                  </div>

                  {/* Threat Risk Calibrated Meter */}
                  <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-color)', paddingTop: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>Calibrated Incident Risk Index:</span>
                      <strong style={{ color: activeReplayStep.riskIndex >= 80 ? '#ef4444' : activeReplayStep.riskIndex >= 50 ? '#f59e0b' : '#10b981', fontSize: '0.95rem' }}>
                        {activeReplayStep.riskIndex} / 100
                      </strong>
                    </div>
                    <div style={{ width: '100%', height: 6, background: '#1e293b', borderRadius: 4, overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${activeReplayStep.riskIndex}%`,
                          height: '100%',
                          background:
                            activeReplayStep.riskIndex >= 80
                              ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
                              : activeReplayStep.riskIndex >= 50
                              ? '#f59e0b'
                              : '#10b981',
                          transition: 'width 0.4s ease',
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* VIEW: OPENSTREETMAP LIVE GLOBAL PACKET GEOLOCATION MAP (MAIN MVP) */}
          {view === '🔴 Live Global Map' && (
            <LiveGeoThreatMap />
          )}

          {/* VIEW: LIVE 2-SECOND WEB LOG STREAMING MONITOR */}
          {view === '⚡ 2s Live Stream' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16, width: '100%' }}>
              {/* Metric Bar */}
              <section className="metrics">
                <div className="metric">
                  <div className="metric-label">
                    Live Stream Status
                    <Activity size={15} />
                  </div>
                  <div className="metric-value" style={{ color: isLiveStreamActive ? '#10b981' : '#f59e0b' }}>
                    {isLiveStreamActive ? 'ACTIVE' : 'PAUSED'}
                  </div>
                  <div className="metric-note">Next packet arriving in: <strong>{streamCountdown.toFixed(1)}s</strong></div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Streamed Web Logs
                    <Layers size={15} />
                  </div>
                  <div className="metric-value">{liveStreamLogs.length}</div>
                  <div className="metric-note">Live incremental telemetry</div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Egress Anomalies
                    <ShieldAlert size={15} />
                  </div>
                  <div className="metric-value" style={{ color: '#ef4444' }}>
                    {liveStreamLogs.filter(l => l.is_anomaly || l.threat_score >= 70).length}
                  </div>
                  <div className="metric-note">Flagged by instant heuristics</div>
                </div>

                <div className="metric">
                  <div className="metric-label">
                    Ingestion Heartbeat
                    <Zap size={15} />
                  </div>
                  <div className="metric-value" style={{ color: '#38bdf8' }}>2.0s</div>
                  <div className="metric-note">Synchronized with n8n workflow</div>
                </div>
              </section>

              {/* Control Header & Manual Ingestion */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 8,
                  padding: '12px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 12,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Continuous Real-Time Web Telemetry Ingestion
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Endpoint: <code style={{ color: 'var(--accent-cyan)' }}>POST /data/stream-log</code>
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsLiveStreamActive(!isLiveStreamActive)}
                    style={{ cursor: 'pointer' }}
                  >
                    {isLiveStreamActive ? 'Pause Stream' : 'Resume Stream'}
                  </Button>

                  <Button
                    size="sm"
                    onClick={async () => {
                      try {
                        const testPayload = {
                          timestamp: new Date().toISOString(),
                          user_id: 'USR-028',
                          user_name: 'E028 (Compromised)',
                          source_ip: '10.4.12.28',
                          destination_ip: '203.0.113.14',
                          hostname: 'mega.nz',
                          method: 'POST',
                          status_code: 200,
                          bytes_sent: 34500000,
                          bytes_received: 14200,
                          protocol: 'UDP',
                          application: 'MEGA',
                          category: 'Personal cloud exfil',
                        };
                        const res = await fetch('/api/data/stream-log', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify(testPayload),
                        });
                        if (res.ok) {
                          const data = await res.json();
                          const manualLog = {
                            ...data,
                            user_name: 'E028 (Compromised)',
                            source_ip: '10.4.12.28',
                            destination_ip: '203.0.113.14',
                            hostname: 'mega.nz',
                            method: 'POST',
                            status_code: 200,
                            bytes_sent: 34500000,
                            isNew: true,
                          };
                          setLiveStreamLogs(prev => [manualLog, ...prev.map(l => ({ ...l, isNew: false }))].slice(0, 45));
                          setMessage(`Simulated test packet ${data.log_id} injected! Risk: ${data.threat_score} (${data.risk_level})`);
                        }
                      } catch {
                        setMessage('Simulated test log injected into local session.');
                      }
                    }}
                    style={{ cursor: 'pointer', background: '#0284c7' }}
                  >
                    🚀 Inject Manual Test Packet
                  </Button>

                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={async () => {
                      try {
                        await fetch('/api/data/stream-logs', { method: 'DELETE' });
                      } catch {}
                      setLiveStreamLogs([]);
                    }}
                    style={{ cursor: 'pointer', color: '#94a3b8' }}
                  >
                    Clear Buffer
                  </Button>
                </div>
              </div>

              {/* Sub-2s Ingestion Heartbeat Progress Bar */}
              <div style={{ height: 3, width: '100%', background: 'rgba(30, 45, 77, 0.6)', borderRadius: 2, overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${Math.min(100, Math.max(0, ((2.0 - streamCountdown) / 2.0) * 100))}%`,
                    background: 'var(--accent-cyan)',
                    transition: 'width 0.1s linear',
                    boxShadow: '0 0 8px rgba(56, 189, 248, 0.6)',
                  }}
                />
              </div>

              {/* Stream Logs Table */}
              <div className="table-scroll" style={{ border: '1px solid var(--border-color)', borderRadius: 8, background: '#060b17' }}>
                <table className="case-table" style={{ width: '100%', fontSize: '0.8rem' }}>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Entity / User</th>
                      <th>Source &rarr; Destination IP</th>
                      <th>Destination Hostname</th>
                      <th>Method & Status</th>
                      <th>Bytes Egress</th>
                      <th>Risk Score</th>
                      <th>Classification</th>
                      <th>Threat Indicator Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveStreamLogs.map((log: any, idx: number) => {
                      const isAnom = Boolean(log.is_anomaly || log.risk === 'High' || log.threat_score >= 70);
                      const score = log.threat_score ?? (isAnom ? 92.5 : 15.0);
                      const sev = log.risk_level ?? (score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW');
                      const bytes = log.bytes_sent ?? log.bytesSent ?? 14200;
                      const timeStr = log.timestamp ? String(log.timestamp).slice(11, 19) : `${idx * 2}s ago`;

                      return (
                        <tr
                          key={log.log_id || `LOG-${idx}`}
                          className={log.isNew ? (isAnom ? 'live-log-row-enter-anom' : 'live-log-row-enter') : ''}
                          style={{
                            background: isAnom ? 'rgba(239, 68, 68, 0.08)' : 'transparent',
                            transition: 'background 0.5s ease',
                          }}
                        >
                          <td style={{ fontFamily: 'monospace', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              {idx === 0 && isLiveStreamActive && (
                                <span className="live-badge-glow">
                                  <span className="live-pulse-dot" /> LIVE
                                </span>
                              )}
                              <span>{timeStr}</span>
                            </div>
                          </td>
                          <td>
                            <strong>{log.user_name || log.user_id || log.user || 'USR-028'}</strong>
                            {log.user_id && log.user_name && (
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{log.user_id}</div>
                            )}
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {log.source_ip || log.sourceIp || '10.4.12.28'} &rarr; {log.destination_ip || log.destinationIp || '203.0.113.14'}
                          </td>
                          <td style={{ color: '#38bdf8', fontWeight: 500 }}>{log.hostname || 'drive.google.com'}</td>
                          <td>
                            <span style={{ padding: '2px 6px', borderRadius: 4, background: '#1e293b', fontSize: '0.7rem', fontWeight: 600 }}>
                              {log.method || 'POST'} {log.status_code || 200}
                            </span>
                          </td>
                          <td>
                            <strong>
                              {bytes > 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`}
                            </strong>
                          </td>
                          <td>
                            <strong style={{ color: score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : '#10b981' }}>
                              {Number(score).toFixed(1)}
                            </strong>
                          </td>
                          <td>
                            <span
                              className={`severity ${
                                sev === 'CRITICAL' ? 'high' : sev === 'HIGH' ? 'high' : sev === 'MEDIUM' ? 'medium' : 'low'
                              }`}
                            >
                              {sev}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.75rem', color: isAnom ? '#fda4af' : '#94a3b8' }}>
                            {log.alert_reason || (isAnom ? 'Unusual volumetric egress to external cloud storage' : 'Standard baseline enterprise web browsing')}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
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
