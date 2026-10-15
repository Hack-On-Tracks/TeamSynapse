import { demoCases, type CaseRecord } from './demo-cases';

const API_BASE = '/api';

export interface GraphSummary {
  node_count: number;
  edge_count: number;
  open_cases: number;
  total_bytes: number;
  unique_sources: number;
  unique_destinations: number;
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
    // Soft fallback
  }
  return { success: false, message: 'Saved to local session (backend offline)' };
}

export async function fetchGraphSummary(): Promise<GraphSummary | null> {
  try {
    const res = await fetch(`${API_BASE}/graph/summary`);
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

export async function fetchAuditLogs(): Promise<AuditLogEntry[]> {
  try {
    const res = await fetch(`${API_BASE}/auth/audit-logs?limit=50`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) return data;
    }
  } catch {}
  return [];
}
