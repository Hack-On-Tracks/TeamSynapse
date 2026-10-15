import { useEffect, useState } from 'react';
import { ArrowDown, ArrowRight, ArrowUp, CircleCheck, CircleDot, EyeOff, Info, LockKeyhole, Pause, Play, Search, SearchCheck, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { caseForFlow, formatBytes, linkedFlows, simulateFlow, type CaseRecord, type FlowRecord, type RiskLevel } from '@/lib/demo-cases';

const SEED_COUNT = 12;
const MAX_ROWS = 25;
const seedFlows = Array.from({ length: SEED_COUNT }, (_, i) => simulateFlow(SEED_COUNT - 1 - i));
const headers = ['Flow ID', 'Case ID', 'Linked Case', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'First Seen', 'Last Seen', 'Duration (seconds)', 'Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received', 'QUIC Version', 'QUIC SNI', 'User Agent', 'Application', 'Category', 'Risk Level', 'Investigation Status'];
const numeric = new Set(['Source Port', 'Destination Port', 'Duration (seconds)', 'Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received']);

const sortFields = { 'First Seen': 'firstSeenAt', 'Last Seen': 'lastSeenAt', 'Duration (seconds)': 'duration', 'Bytes Sent': 'bytesSent', 'Bytes Received': 'bytesReceived' } as const;
type SortLabel = keyof typeof sortFields;
const UNCLASSIFIED = 'Unclassified';
const ALL = 'all';

export type FlowStatus = 'New' | 'Under Investigation' | 'Reviewed';
const statuses: FlowStatus[] = ['New', 'Under Investigation', 'Reviewed'];
const statusIcons = { New: CircleDot, 'Under Investigation': SearchCheck, Reviewed: CircleCheck } as const;

/** Only resolves cases that exist in the session's investigation records; never creates one. */
export const linkedCase = caseForFlow;

/** A flow's review state follows its linked case; flows without a case have not been reviewed yet. */
export function flowStatus(flow: FlowRecord, cases: CaseRecord[]): FlowStatus {
  const status = linkedCase(flow, cases)?.status;
  return status === 'Investigating' ? 'Under Investigation' : status === 'Confirmed' || status === 'Dismissed' ? 'Reviewed' : 'New';
}

export function useFlowStream() {
  const [flows, setFlows] = useState<FlowRecord[]>(seedFlows);
  const [live, setLive] = useState(true);
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(() => setFlows(previous => [simulateFlow((previous[0]?.seq ?? 0) + 1), ...previous].slice(0, MAX_ROWS)), 2000);
    return () => clearInterval(timer);
  }, [live]);
  return { flows, live, setLive };
}
export type FlowStream = ReturnType<typeof useFlowStream>;

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  return <span className={`severity risk-${risk.toLowerCase()}`} aria-label={`Risk level: ${risk}`}>{risk}</span>;
}

export function StatusBadge({ status }: { status: FlowStatus }) {
  const Icon = statusIcons[status];
  return <span className={`flow-status ${status === 'New' ? 'new' : status === 'Reviewed' ? 'reviewed' : 'active'}`}><Icon size={12} aria-hidden/>{status}</span>;
}

const LINKS_SHOWN = 2;

/** Case IDs of other flows with the same source → destination; clicking one opens that flow. */
function LinkedCases({ flow, flows, onSelect, limit = LINKS_SHOWN }: { flow: FlowRecord; flows: FlowRecord[]; onSelect: (flow: FlowRecord) => void; limit?: number }) {
  const links = linkedFlows(flow, flows);
  if (links.length === 0) return <span className="not-available">No linked case</span>;
  const hidden = links.length - limit;
  return <span className="flow-links">{links.slice(0, limit).map(l => <button type="button" key={l.id} className="flow-case-link" aria-label={`Open linked case ${l.caseId}`} onClick={e => { e.stopPropagation(); onSelect(l); }}>{l.caseId}</button>)}
    {hidden > 0 && <button type="button" className="flow-case-link more" aria-label={`Show all ${links.length} linked cases`} onClick={e => { e.stopPropagation(); onSelect(flow); }}>+{hidden}</button>}</span>;
}

function InvestigationCell({ flow, cases, onOpenCase }: { flow: FlowRecord; cases: CaseRecord[]; onOpenCase?: ((caseId: string) => void) | undefined }) {
  const record = linkedCase(flow, cases);
  return <span className="flow-links"><StatusBadge status={flowStatus(flow, cases)}/>{record && <button type="button" className="flow-case-link" aria-label={`Open investigation ${record.id}`} onClick={e => { e.stopPropagation(); onOpenCase?.(record.id); }}>{record.id}</button>}</span>;
}

/** Compact list of a case's flows for the case-detail dialog. */
export function RelatedFlows({ record, flows, onSelect }: { record: CaseRecord; flows: FlowRecord[]; onSelect: (flow: FlowRecord) => void }) {
  const related = flows.filter(f => linkedCase(f, [record]));
  return <section className="related-flows"><h2>Related network flows<span className="inline-count">{related.length} in the current capture</span></h2><p className="related-flows-key">Linked by source → destination: <span className="font-mono">{record.sourceIp} → {record.destinationIp}</span></p>
    {related.length === 0 ? <p className="text-[11px] text-muted-foreground">No flows for this case in the current capture window.</p>
      : <ul>{related.map(f => <li key={f.id}><button type="button" onClick={() => onSelect(f)}><span className="font-mono">{f.id}</span><span className="font-mono text-muted-foreground">{f.lastSeen}</span><span className="text-muted-foreground">{f.hostname ?? f.destinationIp}</span><span>{formatBytes(f.bytesSent)} out</span><RiskBadge risk={f.risk}/><ArrowRight size={13} aria-hidden/></button></li>)}</ul>}
  </section>;
}

function Meta({ value, mono = false }: { value: string | null; mono?: boolean }) {
  return value === null ? <span className="not-available">N/A</span> : <span className={mono ? 'font-mono' : ''}>{value}</span>;
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return <Select value={value} onValueChange={onChange}><SelectTrigger className="flow-select" aria-label={label}><SelectValue/></SelectTrigger><SelectContent>
    <SelectItem value={ALL}>All {label.toLowerCase()}</SelectItem>{options.map(o => <SelectItem key={o} value={o}>{o}</SelectItem>)}
  </SelectContent></Select>;
}

/** Plain-language description of what the flow's metadata shows. Never derived from payload content. */
function summarise(f: FlowRecord, record: CaseRecord | null, links: FlowRecord[]) {
  const lines: string[] = [];
  const ratio = f.bytesSent / Math.max(1, f.bytesReceived);
  const volume = ratio >= 3 ? `Upload-heavy: the source sent ${Math.round(ratio)}× more data than it received` : ratio <= 1 / 3 ? `Download-heavy: the source received ${Math.round(1 / ratio)}× more data than it sent` : 'Roughly balanced traffic in both directions';
  lines.push(`${volume} (${formatBytes(f.bytesSent)} out, ${formatBytes(f.bytesReceived)} in), with an average outbound packet size of ${Math.round(f.bytesSent / Math.max(1, f.packetsSent)).toLocaleString('en-US')} B.`);
  lines.push(f.duration > 0 ? `The connection lasted ${f.duration} s, averaging ${formatBytes(Math.round(f.bytesSent / f.duration))}/s outbound.` : 'A single request and response exchanged in under one second.');
  if (f.quicVersion) lines.push(`QUIC ${f.quicVersion} over UDP ${f.destinationPort}. The server name ${f.quicSni ?? 'was not'} is visible in the handshake; everything after it is encrypted.`);
  else if (f.userAgent) lines.push(`Unencrypted HTTP on port ${f.destinationPort}, so the client's user agent header is visible in the metadata.`);
  else if (f.destinationPort === 443) lines.push(`TLS over TCP ${f.destinationPort}. ${f.hostname ? `Hostname ${f.hostname} was observed from connection metadata.` : 'No hostname was observed for this destination.'}`);
  else if (f.destinationPort === 53) lines.push('A DNS lookup to the internal resolver.');
  else if (f.destinationPort === 22) lines.push('An SSH session to an internal host. The session contents are encrypted.');
  lines.push(f.application ? `Classified as ${f.application} (${f.category ?? 'no category'}).` : `The application could not be identified${f.category ? `, but the destination is in the ${f.category} category` : ''}.`);
  if (links.length) lines.push(`${links.length} other flow${links.length === 1 ? '' : 's'} in the current capture share this source and destination, so ${links.length === 1 ? 'its case is' : 'their cases are'} linked to ${f.caseId}.`);
  if (record) lines.push(`This source → destination pair belongs to investigation ${record.id}, which is currently ${record.status.toLowerCase()}.`);
  return lines;
}

export function NetworkFlows({ stream, cases, selected, onSelect, onOpenCase }: { stream: FlowStream; cases: CaseRecord[]; selected: FlowRecord | null; onSelect: (flow: FlowRecord | null) => void; onOpenCase?: (caseId: string) => void }) {
  const { flows, live, setLive } = stream;
  const [query, setQuery] = useState('');
  const [protocol, setProtocol] = useState(ALL);
  const [category, setCategory] = useState(ALL);
  const [status, setStatus] = useState(ALL);
  const [sortBy, setSortBy] = useState<SortLabel>('Last Seen');
  const [descending, setDescending] = useState(true);
  const setSelected = onSelect;
  const statusOf = (f: FlowRecord) => flowStatus(f, cases);
  const categories = [...new Set(flows.map(f => f.category ?? UNCLASSIFIED))].sort();
  const needle = query.trim().toLowerCase();
  const field = sortFields[sortBy];
  const visible = flows
    .filter(f => !needle || [f.id, f.caseId, linkedCase(f, cases)?.id ?? null, f.sourceIp, f.destinationIp, f.hostname, f.quicSni, f.application].some(v => v?.toLowerCase().includes(needle)))
    .filter(f => protocol === ALL || f.protocol === protocol)
    .filter(f => category === ALL || (f.category ?? UNCLASSIFIED) === category)
    .filter(f => status === ALL || statusOf(f) === status)
    .sort((a, b) => (descending ? b[field] - a[field] : a[field] - b[field]) || b.seq - a.seq);
  const filtersActive = needle !== '' || protocol !== ALL || category !== ALL || status !== ALL;
  function clearFilters() { setQuery(''); setProtocol(ALL); setCategory(ALL); setStatus(ALL); }
  function sortOn(label: SortLabel) { if (label === sortBy) setDescending(!descending); else { setSortBy(label); setDescending(true); } }

  return <div className="flows-block">
    <div className="section-title"><h2>Network flows<span className="inline-count">{filtersActive ? `${visible.length} of ${flows.length} flows match` : `${flows.length} flows`}</span><span className="demo-tag ml-2">Simulated data</span></h2><span className="flow-live"><span className={`status-dot ${live ? 'pulsing' : 'paused'}`}/>{live ? 'Streaming · every 2s' : 'Paused'}<Button variant="outline" size="sm" className="ml-3" onClick={() => setLive(!live)}>{live ? <><Pause/>Pause</> : <><Play/>Resume</>}</Button></span></div>
    <div className="queue">
      <div className="queue-toolbar flow-toolbar">
        <label className="search-field"><Search size={13}/><input aria-label="Search flows" placeholder="Flow ID, case ID, IP, hostname, application..." value={query} onChange={e => setQuery(e.target.value)}/></label>
        <div className="flow-controls">
          <FilterSelect label="Protocols" value={protocol} options={['TCP', 'UDP']} onChange={setProtocol}/>
          <FilterSelect label="Categories" value={category} options={categories} onChange={setCategory}/>
          <FilterSelect label="Statuses" value={status} options={statuses} onChange={setStatus}/>
          <span className="flow-sort"><Select value={sortBy} onValueChange={v => setSortBy(v as SortLabel)}><SelectTrigger className="flow-select" aria-label="Sort by"><span className="text-muted-foreground">Sort:</span><SelectValue/></SelectTrigger><SelectContent>{Object.keys(sortFields).map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent></Select>
            <Button variant="outline" size="icon" className="flow-direction-toggle" aria-label={descending ? 'Sorted descending' : 'Sorted ascending'} title={descending ? 'Descending' : 'Ascending'} onClick={() => setDescending(!descending)}>{descending ? <ArrowDown/> : <ArrowUp/>}</Button></span>
          <Button variant="ghost" size="sm" className="filter" disabled={!filtersActive} onClick={clearFilters}><X/>Clear filters</Button>
        </div>
      </div>
      <div className="table-scroll flow-scroll"><table className="case-table flow-table"><thead><tr>{headers.map(h => {
        const sortable = h in sortFields;
        return <th key={h} className={numeric.has(h) ? 'numeric' : ''} aria-sort={sortBy === h ? (descending ? 'descending' : 'ascending') : undefined}>{sortable ? <button type="button" className={`flow-sort-header ${sortBy === h ? 'active' : ''}`} onClick={() => sortOn(h as SortLabel)}>{h}{sortBy === h && (descending ? <ArrowDown size={11}/> : <ArrowUp size={11}/>)}</button> : h}</th>;
      })}</tr></thead>
        <tbody>{visible.map(f => <tr key={f.id} className={selected?.id === f.id ? 'selected' : ''} tabIndex={0} onClick={() => setSelected(f)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(f); } }}>
          <td className="font-mono">{f.id}</td>
          <td className="font-mono">{f.caseId}</td>
          <td><LinkedCases flow={f} flows={flows} onSelect={setSelected}/></td>
          <td className="font-mono">{f.sourceIp}</td>
          <td className="font-mono">{f.destinationIp}</td>
          <td className="numeric font-mono">{f.sourcePort}</td>
          <td className="numeric font-mono">{f.destinationPort}</td>
          <td>{f.protocol}</td>
          <td className="font-mono">{f.firstSeen}</td>
          <td className="font-mono">{f.lastSeen}</td>
          <td className="numeric">{f.duration}</td>
          <td className="numeric" title={`${f.bytesSent.toLocaleString('en-US')} bytes`}>{formatBytes(f.bytesSent)}</td>
          <td className="numeric" title={`${f.bytesReceived.toLocaleString('en-US')} bytes`}>{formatBytes(f.bytesReceived)}</td>
          <td className="numeric">{f.packetsSent.toLocaleString('en-US')}</td>
          <td className="numeric">{f.packetsReceived.toLocaleString('en-US')}</td>
          <td><Meta value={f.quicVersion}/></td>
          <td><Meta value={f.quicSni} mono/></td>
          <td><Meta value={f.userAgent}/></td>
          <td><Meta value={f.application}/></td>
          <td><Meta value={f.category}/></td>
          <td><RiskBadge risk={f.risk}/></td>
          <td><InvestigationCell flow={f} cases={cases} onOpenCase={onOpenCase}/></td>
        </tr>)}</tbody></table>
        {flows.length === 0 ? <div className="empty-state">No network flows recorded for this period.</div>
          : visible.length === 0 && <div className="empty-state"><p>No flows match the current search and filters.</p><p className="mt-1 text-[10px]">{live ? 'New flows are still streaming in and will appear here if they match.' : 'Try a broader search, or resume streaming to receive new flows.'}</p><Button variant="outline" size="sm" className="mt-3" onClick={clearFilters}><X/>Clear filters</Button></div>}
      </div>
      <div className="queue-footer"><span>{visible.length} of {flows.length} flows shown · sorted by {sortBy.toLowerCase()} ({descending ? 'descending' : 'ascending'}) · illustrative IP addresses (RFC 1918 / RFC 5737)</span><span className="flex items-center gap-1"><LockKeyhole size={11}/>Metadata only · no payloads decrypted or displayed</span></div>
    </div>
    <Sheet open={selected !== null} onOpenChange={open => { if (!open) setSelected(null); }}>
      <SheetContent className="flow-drawer">{selected && <FlowDetail flow={selected} flows={flows} cases={cases} onSelect={setSelected} onOpenCase={onOpenCase}/>}</SheetContent>
    </Sheet>
  </div>;
}

function FlowDetail({ flow: f, flows, cases, onSelect, onOpenCase }: { flow: FlowRecord; flows: FlowRecord[]; cases: CaseRecord[]; onSelect: (flow: FlowRecord) => void; onOpenCase?: ((caseId: string) => void) | undefined }) {
  const record = linkedCase(f, cases);
  const links = linkedFlows(f, flows);
  const status = flowStatus(f, cases);
  const groups: { title: string; rows: [string, string | number | null, boolean?][] }[] = [
    { title: 'Timing', rows: [['First seen', f.firstSeen, true], ['Last seen', f.lastSeen, true], ['Duration', `${f.duration} s`]] },
    { title: 'Endpoints', rows: [['Source IP', f.sourceIp, true], ['Source port', f.sourcePort, true], ['Destination IP', f.destinationIp, true], ['Destination port', f.destinationPort, true], ['Hostname', f.hostname, true], ['Protocol', f.protocol]] },
    { title: 'Volume', rows: [['Bytes sent', `${formatBytes(f.bytesSent)} (${f.bytesSent.toLocaleString('en-US')} B)`], ['Bytes received', `${formatBytes(f.bytesReceived)} (${f.bytesReceived.toLocaleString('en-US')} B)`], ['Packets sent', f.packetsSent.toLocaleString('en-US')], ['Packets received', f.packetsReceived.toLocaleString('en-US')]] },
    { title: 'Handshake & client', rows: [['QUIC version', f.quicVersion], ['QUIC SNI', f.quicSni, true], ['User agent', f.userAgent]] },
    { title: 'Classification', rows: [['Application', f.application], ['Category', f.category]] },
  ];
  return <div className="flow-detail">
    <div><span className="case-ref">{f.id} · SIMULATED METADATA</span><SheetTitle className="mt-2">{f.application ?? f.hostname ?? f.destinationIp}</SheetTitle><SheetDescription className="font-mono text-[11px] mt-1">{f.sourceIp}:{f.sourcePort} → {f.destinationIp}:{f.destinationPort} · {f.protocol}</SheetDescription></div>
    <dl className="flow-fields flow-assessment">
      <div><dt>Risk level</dt><dd><RiskBadge risk={f.risk}/></dd></div>
      <div><dt>Case ID</dt><dd className="font-mono">{f.caseId}</dd></div>
      <div><dt>Investigation status</dt><dd><StatusBadge status={status}/></dd></div>
      <div><dt>Investigation</dt><dd>{record ? <span className="font-mono">{record.id} · {record.status}</span> : <span className="not-available">None</span>}</dd></div>
    </dl>
    <section><h3>Linked cases · {links.length}</h3><p className="related-flows-key">Other flows with the same source → destination: <span className="font-mono">{f.sourceIp} → {f.destinationIp}</span></p>
      {links.length === 0 ? <p className="not-available">No linked case</p> : <LinkedCases flow={f} flows={flows} onSelect={onSelect} limit={links.length}/>}
    </section>
    <section><h3>Risk signals</h3>{f.risk === 'Unassessed'
      ? <p className="flow-signal-empty">This flow has not been risk-assessed, so no level or confidence is shown.</p>
      : f.signals.length === 0 ? <p className="flow-signal-empty">This flow was assessed, and no unusual signals were observed against the illustrative baselines.</p>
      : <ul className="flow-signals">{f.signals.map(s => <li key={s.kind}><Info size={14} aria-hidden/><div><strong>{s.title}</strong><p>{s.detail}</p></div></li>)}</ul>}
      <p className="flow-caveat">Signals are prompts for human review, not proof of data theft or intent. Nothing is blocked automatically, and no disciplinary decision is made from these signals.</p>
    </section>
    <section className="flow-summary"><h3>Metadata summary</h3><ul>{summarise(f, record, links).map(line => <li key={line}>{line}</li>)}</ul></section>
    {groups.map(g => <section key={g.title}><h3>{g.title}</h3><dl className="flow-fields">{g.rows.map(([label, value, mono]) => <div key={label}><dt>{label}</dt><dd className={mono && value !== null ? 'font-mono' : ''}>{value === null ? <span className="not-available">N/A</span> : value}</dd></div>)}</dl></section>)}
    {record && onOpenCase && <Button size="sm" className="w-full" onClick={() => onOpenCase(record.id)}>Open investigation {record.id}<ArrowRight/></Button>}
    <p className="flow-privacy"><EyeOff size={13}/>Only connection metadata is shown. Payloads are not decrypted and message contents are not available.</p>
  </div>;
}
