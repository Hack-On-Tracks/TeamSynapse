export type CaseRecord = {
  id: string;
  title: string;
  user: string;
  team: string;
  destination: string;
  category: string;
  severity: 'high' | 'medium' | 'low';
  risk: number;
  confidence: number;
  pattern: string;
  seen: string;
  bytes: string;
  days: number;
  status: 'Open' | 'Investigating' | 'Confirmed' | 'Dismissed';
  /** Flows from this source IP to this destination IP are linked to the case. */
  sourceIp: string;
  destinationIp: string;
  analystNote?: string;
};

export const demoCases: CaseRecord[] = [
  { id: 'CS-0042', title: 'Persistent uploads to personal cloud', user: 'USR-028', team: 'Engineering', destination: 'drive.google.com', category: 'Personal cloud', severity: 'high', risk: 92, confidence: 94, pattern: 'Low & slow', seen: '12 min ago', bytes: '284 MB', days: 14, status: 'Open', sourceIp: '10.4.12.28', destinationIp: '203.0.113.14' },
  { id: 'CS-0041', title: 'Unusual after-hours transfer', user: 'USR-061', team: 'Finance', destination: 'dropbox.com', category: 'File sharing', severity: 'high', risk: 87, confidence: 91, pattern: 'Burst upload', seen: '38 min ago', bytes: '1.2 GB', days: 2, status: 'Investigating', sourceIp: '10.6.3.61', destinationIp: '198.51.100.18' },
  { id: 'CS-0040', title: 'Recurring overnight connections', user: 'USR-015', team: 'Sales', destination: 'mega.nz', category: 'Personal cloud', severity: 'medium', risk: 74, confidence: 88, pattern: 'Scheduled', seen: '1 hour ago', bytes: '368 MB', days: 7, status: 'Open', sourceIp: '10.2.8.15', destinationIp: '203.0.113.135' },
  { id: 'CS-0039', title: 'Outbound volume above peer baseline', user: 'USR-043', team: 'Engineering', destination: 's3.amazonaws.com', category: 'Cloud storage', severity: 'medium', risk: 68, confidence: 82, pattern: 'Slow ramp', seen: '2 hours ago', bytes: '196 MB', days: 11, status: 'Open', sourceIp: '10.4.15.43', destinationIp: '198.51.100.40' },
  { id: 'CS-0038', title: 'New destinations across multiple sessions', user: 'USR-072', team: 'Support', destination: 'Multiple destinations', category: '12 new destinations', severity: 'low', risk: 46, confidence: 76, pattern: 'Rotation', seen: '3 hours ago', bytes: '82 MB', days: 3, status: 'Open', sourceIp: '10.8.1.72', destinationIp: '192.0.2.9' },
];

export function downloadEvidence(cases: CaseRecord[], name = 'cipher-sentinel-evidence') {
  const blob = new Blob([JSON.stringify({ source: 'CipherSentinel Investigation Engine', exportedAt: new Date().toISOString(), cases }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${name}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export type FlowRecord = {
  id: string;
  caseId: string;
  seq: number;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: 'TCP' | 'UDP';
  firstSeen: string;
  lastSeen: string;
  firstSeenAt: number;
  lastSeenAt: number;
  duration: number;
  bytesSent: number;
  bytesReceived: number;
  packetsSent: number;
  packetsReceived: number;
  quicVersion: string | null;
  quicSni: string | null;
  userAgent: string | null;
  application: string | null;
  category: string | null;
  hostname: string | null;
  risk: RiskLevel;
  signals: FlowSignal[];
};

export type RiskLevel = 'High' | 'Medium' | 'Low' | 'Unassessed';
export type SignalKind = 'high-volume' | 'new-destination' | 'small-transfers' | 'timing' | 'baseline';
export type FlowSignal = { kind: SignalKind; title: string; detail: string };

export const signalTitles: Record<SignalKind, string> = {
  'high-volume': 'Unusually high outbound byte volume',
  'new-destination': 'Previously unseen destination',
  'small-transfers': 'Repeated small outbound transfers',
  timing: 'Unusual connection timing',
  baseline: "Differs from the user's or peer group's baseline",
};

type FlowProfile = {
  src: string;
  dst: string;
  protocol: FlowRecord['protocol'];
  port: number;
  quicVersion: string | null;
  quicSni: string | null;
  userAgent: string | null;
  application: string | null;
  category: string | null;
  hostname: string | null;
  upload: boolean;
  pktSize: [number, number];
  maxSeconds: number;
  maxPackets?: number;
  risk: Exclude<RiskLevel, 'Unassessed'> | null;
  signals: SignalKind[];
};

const flowProfiles: FlowProfile[] = [
  { src: '10.4.12.28', dst: '203.0.113.14', protocol: 'UDP', port: 443, quicVersion: 'v1', quicSni: 'drive.google.com', userAgent: null, hostname: 'drive.google.com', risk: 'High', signals: ['small-transfers', 'baseline'], application: 'Google Drive', category: 'Personal cloud', upload: true, pktSize: [1180, 1350], maxSeconds: 90, maxPackets: 110 },
  { src: '10.6.3.61', dst: '198.51.100.18', protocol: 'TCP', port: 443, quicVersion: null, quicSni: null, userAgent: null, hostname: 'content.dropboxapi.com', risk: 'High', signals: ['high-volume', 'baseline'], application: 'Dropbox', category: 'File sharing', upload: true, pktSize: [1300, 1460], maxSeconds: 240 },
  { src: '10.2.8.15', dst: '203.0.113.135', protocol: 'TCP', port: 443, quicVersion: null, quicSni: null, userAgent: null, hostname: 'gfs270n113.userstorage.mega.co.nz', risk: 'Medium', signals: ['timing', 'baseline'], application: 'MEGA', category: 'Personal cloud', upload: true, pktSize: [900, 1380], maxSeconds: 180 },
  { src: '10.4.15.43', dst: '198.51.100.40', protocol: 'TCP', port: 443, quicVersion: null, quicSni: null, userAgent: null, hostname: 'ext-bucket.s3.amazonaws.com', risk: 'Medium', signals: ['high-volume', 'baseline'], application: 'Amazon S3', category: 'Cloud storage', upload: true, pktSize: [1000, 1460], maxSeconds: 120 },
  { src: '10.8.1.72', dst: '192.0.2.9', protocol: 'TCP', port: 443, quicVersion: null, quicSni: null, userAgent: null, hostname: null, risk: 'Low', signals: ['new-destination'], application: null, category: null, upload: true, pktSize: [400, 1200], maxSeconds: 60 },
  { src: '10.2.9.33', dst: '203.0.113.78', protocol: 'UDP', port: 443, quicVersion: 'v1', quicSni: 'www.youtube.com', userAgent: null, hostname: 'www.youtube.com', risk: 'Low', signals: [], application: 'YouTube', category: 'Streaming media', upload: false, pktSize: [1200, 1350], maxSeconds: 600 },
  { src: '10.6.7.66', dst: '192.0.2.193', protocol: 'UDP', port: 443, quicVersion: 'v2', quicSni: 'edge.example.com', userAgent: null, hostname: 'edge.example.com', risk: null, signals: [], application: null, category: 'CDN', upload: false, pktSize: [600, 1300], maxSeconds: 45 },
  { src: '10.6.2.19', dst: '198.51.100.14', protocol: 'TCP', port: 443, quicVersion: null, quicSni: null, userAgent: null, hostname: 'outlook.office.com', risk: 'Low', signals: [], application: 'Microsoft 365', category: 'Collaboration', upload: false, pktSize: [300, 1100], maxSeconds: 300 },
  { src: '10.4.11.4', dst: '192.0.2.80', protocol: 'TCP', port: 80, quicVersion: null, quicSni: null, userAgent: 'Microsoft-Delivery-Optimization/10.0', hostname: 'download.windowsupdate.com', risk: 'Low', signals: [], application: 'Windows Update', category: 'Software update', upload: false, pktSize: [1200, 1460], maxSeconds: 400 },
  { src: '10.8.4.50', dst: '10.20.0.53', protocol: 'UDP', port: 53, quicVersion: null, quicSni: null, userAgent: null, hostname: 'resolver.internal', risk: null, signals: [], application: 'DNS', category: 'Infrastructure', upload: false, pktSize: [70, 180], maxSeconds: 1 },
  { src: '10.4.14.57', dst: '10.20.0.12', protocol: 'TCP', port: 22, quicVersion: null, quicSni: null, userAgent: null, hostname: 'build-runner.internal', risk: 'Low', signals: [], application: 'SSH', category: 'Remote access', upload: true, pktSize: [90, 600], maxSeconds: 900 },
];

function seeded(seq: number, salt: number) {
  const x = Math.sin(seq * 9301 + salt * 49297) * 233280;
  return x - Math.floor(x);
}

function clock(seconds: number) {
  return [Math.floor(seconds / 3600) % 24, Math.floor(seconds / 60) % 60, seconds % 60].map(n => String(Math.floor(n)).padStart(2, '0')).join(':');
}

export function simulateFlow(seq: number): FlowRecord {
  const p = flowProfiles[Math.floor(seeded(seq, 1) * flowProfiles.length)] ?? flowProfiles[0]!;
  const [min, max] = p.pktSize;
  const size = () => Math.round(min + seeded(seq, 3) * (max - min));
  const bulk = 20 + Math.floor(seeded(seq, 2) * (p.maxPackets ?? 900));
  const acks = Math.max(1, Math.round(bulk * (0.3 + seeded(seq, 5) * 0.3)));
  const packetsSent = p.port === 53 ? 1 : p.upload ? bulk : acks;
  const packetsReceived = p.port === 53 ? 1 : p.upload ? acks : bulk;
  const bytesSent = p.port === 53 ? size() : p.upload ? packetsSent * size() : packetsSent * 66;
  const bytesReceived = p.port === 53 ? size() + 48 : p.upload ? packetsReceived * 66 : packetsReceived * size();
  const duration = p.maxSeconds <= 1 ? 0 : Math.max(1, Math.round(seeded(seq, 6) * p.maxSeconds));
  const last = 9 * 3600 + 53 * 60 + seq * 2;
  const destination = p.hostname ?? p.dst;
  const details: Record<SignalKind, string> = {
    'high-volume': `This flow sent ${formatBytes(bytesSent)} in ${duration} s. The user's typical outbound volume to ${p.category?.toLowerCase() ?? 'this category'} is under 50 KB per connection (baseline comparison).`,
    'new-destination': `${destination} had not been contacted by anyone in this workspace in the previous 30 days. The application could not be identified.`,
    'small-transfers': `This is one of many short uploads to ${destination}. Each is small (this one is ${formatBytes(bytesSent)}), but together they add up to far more than usual volume.`,
    timing: `Connections to ${destination} repeat at a regular ~20-minute interval, including overnight. That machine-like schedule differs from usual interactive activity.`,
    baseline: `Few people in this user's peer group connect to ${destination}, and this user had not done so before this period.`,
  };

  return {
    id: `FL-${String(18420 + seq).padStart(6, '0')}`,
    caseId: `FC-${String(18420 + seq).padStart(6, '0')}`,
    seq,
    sourceIp: p.src,
    destinationIp: p.dst,
    sourcePort: 49152 + Math.floor(seeded(seq, 4) * 16000),
    destinationPort: p.port,
    protocol: p.protocol,
    firstSeen: clock(last - duration),
    lastSeen: clock(last),
    firstSeenAt: last - duration,
    lastSeenAt: last,
    duration,
    bytesSent,
    bytesReceived,
    packetsSent,
    packetsReceived,
    quicVersion: p.quicVersion,
    quicSni: p.quicSni,
    userAgent: p.userAgent,
    application: p.application,
    category: p.category,
    hostname: p.hostname,
    risk: p.risk ?? 'Unassessed',
    signals: p.signals.map(kind => ({ kind, title: signalTitles[kind], detail: details[kind] })),
  };
}

export function caseForFlow(flow: FlowRecord, cases: CaseRecord[]) {
  return cases.find(c => c.sourceIp === flow.sourceIp && c.destinationIp === flow.destinationIp) ?? null;
}

export function linkedFlows(flow: FlowRecord, flows: FlowRecord[]) {
  return flows.filter(f => f.id !== flow.id && f.sourceIp === flow.sourceIp && f.destinationIp === flow.destinationIp);
}

export function formatBytes(bytes: number) {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}
