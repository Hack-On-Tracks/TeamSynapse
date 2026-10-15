import { demoCases, type CaseRecord } from './demo-cases';

const API_BASE = '/api';

export interface GraphSummary {
  node_count: number;
  edge_count: number;
  open_cases: number;
  total_bytes: number;
  unique_sources: number;
  unique_destinations: number;
  high_risk_nodes?: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  event_type: string;
  username: string;
  status: string;
  details: string;
  ip_address: string;
}

export async function fetchLiveCases(): Promise<{ cases: CaseRecord[]; isBackend: boolean }> {
  try {
    const res = await fetch(`${API_BASE}/score/cases`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (Array.isArray(data) && data.length > 0) {
      const mapped: CaseRecord[] = data.map((c: any) => {
        let sev: 'high' | 'medium' | 'low' = 'medium';
        const rawSev = (c.severity || '').toLowerCase();
        if (rawSev === 'critical' || rawSev === 'high') sev = 'high';
        else if (rawSev === 'low') sev = 'low';

        let st: CaseRecord['status'] = 'Open';
        const rawSt = (c.status || '').toUpperCase();
        if (rawSt === 'INVESTIGATING') st = 'Investigating';
        else if (rawSt === 'CONFIRMED' || rawSt === 'MITIGATED') st = 'Confirmed';
        else if (rawSt === 'DISMISSED' || rawSt === 'FALSE_POSITIVE') st = 'Dismissed';

        return {
          id: c.case_id,
          title: c.title || `Investigation on ${c.entity_id}`,
          user: c.entity_id || 'USR-ANON',
          team: c.team || 'Security operations',
          destination: c.destination || c.evidence_summary || 'External Destination',
          category: c.category || 'Threat Anomaly',
          severity: sev,
          risk: Math.round(c.case_score ?? 80),
          confidence: Math.round(c.confidence ?? 90),
          pattern: c.pattern || 'Multi-vector telemetry',
          seen: c.created_at ? new Date(c.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recently',
          bytes: c.total_bytes ? `${(c.total_bytes / 1024 / 1024).toFixed(1)} MB` : '184 MB',
          days: c.days || 7,
          status: st,
          sourceIp: c.source_ip || '10.4.12.28',
          destinationIp: c.destination_ip || '203.0.113.14',
          analystNote: c.analyst_note || '',
        };
      });
      return { cases: mapped, isBackend: true };
    }
  } catch {
    // Backend offline or empty
  }
  return { cases: demoCases, isBackend: false };
}

export async function updateCaseStatus(
  caseId: string,
  status: CaseRecord['status'],
  note?: string
): Promise<{ success: boolean; message: string }> {
  const backendStatusMap: Record<CaseRecord['status'], string> = {
    Open: 'OPEN',
    Investigating: 'INVESTIGATING',
    Confirmed: 'CONFIRMED',
    Dismissed: 'DISMISSED',
  };

  try {
    const res = await fetch(`${API_BASE}/score/case/${caseId}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: backendStatusMap[status] || 'OPEN',
        analyst_note: note || '',
      }),
    });
    if (res.ok) {
      const data = await res.json();
      return { success: true, message: data.message || `Case ${caseId} updated successfully in DuckDB` };
    }
  } catch {
    // If backend isn't reachable, return soft response
  }
  return { success: false, message: 'Saved to local session (backend offline)' };
}

export async function fetchGraphSummary(): Promise<GraphSummary | null> {
  try {
    const res = await fetch(`${API_BASE}/graph/summary`);
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Fallback
  }
  return null;
}

export async function fetchAuditLogs(): Promise<AuditLogEntry[]> {
  try {
    const res = await fetch(`${API_BASE}/auth/audit-logs?limit=50`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) return data;
    }
  } catch {
    // Fallback
  }
  return [];
}

export interface ModelInfo {
  loaded: boolean;
  model_type?: string;
  scaler_type?: string;
  n_features?: number;
  features?: string[];
  n_estimators?: number;
  contamination?: number;
  offset?: number;
}

export async function fetchModelInfo(): Promise<ModelInfo | null> {
  try {
    const res = await fetch(`${API_BASE}/detect/model/info`);
    if (res.ok) return await res.json();
  } catch {
    // Fallback
  }
  return null;
}

export async function runModelPredict(records?: any[], tableName?: string): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/detect/model/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records, table_name: tableName }),
    });
    if (res.ok) return await res.json();
  } catch {
    // Fallback
  }
  return null;
}

// ---------------------------------------------------------------------
// Multi-Layer Consensus & Zero False-Opposite Types & API
// ---------------------------------------------------------------------

export interface RuleLayerResult {
  entity_id: string;
  rule_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  rules_triggered: string[];
  rule_count: number;
  sub_volume: number;
  sub_novelty: number;
  sub_timing: number;
  sub_auth: number;
  sub_dns: number;
  primary_rule_indicator: string;
}

export interface MLDeviation {
  feature: string;
  z_deviation: number;
}

export interface MLLayerResult {
  entity_id: string;
  model_type: string;
  ml_score: number;
  is_anomaly: boolean;
  decision_status: 'OUTLIER' | 'INLIER';
  top_deviations: MLDeviation[];
  raw_contamination: number;
}

export interface OllamaLayerResult {
  entity_id: string;
  model: string;
  verdict: 'CONFIRMED_THREAT' | 'LIKELY_FALSE_POSITIVE' | 'SUSPICIOUS_INVESTIGATE' | 'BENIGN_OPERATION';
  confidence: number;
  rationale: string;
  thinking?: string;
  is_live_call?: boolean;
}

export interface ConsensusRecord {
  entity_id: string;
  rule_layer: RuleLayerResult;
  ml_layer: MLLayerResult;
  ollama_layer: OllamaLayerResult;
  consensus_status: string;
  is_false_opposite: boolean;
  false_opposite_type: string;
  final_calibrated_risk: number;
  final_severity: string;
  recommended_action: string;
  consensus_explanation: string;
}

import defaultConsensusData from './consensus-data.json';

export async function fetchConsensusScores(liveOllama: boolean = false): Promise<ConsensusRecord[]> {
  try {
    const res = await fetch(`${API_BASE}/score/consensus?live_ollama=${liveOllama}`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        return data as ConsensusRecord[];
      }
    }
  } catch {
    // Backend offline or error -> fallback to curated multi-engine dataset
  }
  return defaultConsensusData as ConsensusRecord[];
}

export async function runLiveOllamaVerify(entityId: string, indicators: any): Promise<OllamaLayerResult | null> {
  try {
    const res = await fetch(`${API_BASE}/genai/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: entityId, indicators }),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Fallback
  }
  return null;
}

