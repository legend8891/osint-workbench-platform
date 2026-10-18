import JSZip from 'jszip';
import type {
  CaseRecord,
  CorrelationHit,
  Confidence,
  EntityRecord,
  EvidenceRecord,
  RelationshipRecord,
} from 'shared';
import { promoteConfidence } from 'shared';
import { escapeXml, escapeHtml } from './escape';

function normalizeToken(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, ' ');
}

export function buildCorrelationHits(cases: CaseRecord[]): CorrelationHit[] {
  const tokenMap = new Map<string, CorrelationHit['matches']>();
  for (const record of cases) {
    for (const entity of record.entities) {
      for (const identifier of entity.identifiers) {
        const token = normalizeToken(identifier);
        if (!token) continue;
        const list = tokenMap.get(token) ?? [];
        list.push({
          caseId: record.id,
          caseName: record.name,
          entityId: entity.id,
          entityName: entity.name,
          entityType: entity.type,
        });
        tokenMap.set(token, list);
      }
    }
  }
  return [...tokenMap.entries()]
    .filter(([, matches]) => new Set(matches.map((m) => m.caseId)).size > 1)
    .map(([token, matches]) => ({ token, matches }));
}

export function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^\w.\- ]+/g, '_').trim() || 'case';
}

export function exportHtmlReport(record: CaseRecord, correlationHits: CorrelationHit[]) {
  const hitsHtml = correlationHits
    .map(
      (h) =>
        '<li><strong>' +
        escapeHtml(h.token) +
        '</strong> — ' +
        h.matches.length +
        ' matches<ul>' +
        h.matches
          .map(
            (m) =>
              '<li>' +
              escapeHtml(m.caseName) +
              ' / ' +
              escapeHtml(m.entityName) +
              ' (' +
              escapeHtml(m.entityType) +
              ')</li>'
          )
          .join('') +
        '</ul></li>'
    )
    .join('');

  const html =
    '<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>' +
    escapeHtml(record.name) +
    ' — OSINT Report</title></head><body><h1>' +
    escapeHtml(record.name) +
    '</h1><p>' +
    escapeHtml(record.report.summary) +
    '</p><p>' +
    escapeHtml(record.report.next) +
    '</p><h2>Entities</h2><ul>' +
    record.entities
      .map(
        (e) =>
          '<li><strong>' +
          escapeHtml(e.name) +
          '</strong> (' +
          escapeHtml(e.type) +
          ') — ' +
          escapeHtml(e.confidence) +
          '</li>'
      )
      .join('') +
    '</ul><h2>Correlation</h2>' +
    (correlationHits.length ? '<ul>' + hitsHtml + '</ul>' : '<p>None</p>') +
    '</body></html>';

  const blob = new Blob([html], { type: 'text/html' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = record.name + '.html';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export async function exportBundleZip(record: CaseRecord, correlationHits: CorrelationHit[]) {
  const zip = new JSZip();
  zip.file('case.json', JSON.stringify(record, null, 2));
  zip.file('correlations.json', JSON.stringify(correlationHits, null, 2));
  zip.file('graph.graphml', buildGraphML(record, correlationHits));
  const blob = await zip.generateAsync({ type: 'blob' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = record.name + '.zip';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export function buildGraphML(
  record: CaseRecord,
  _correlationHits: CorrelationHit[] = []
): string {
  const entityIds = new Set(record.entities.map((e) => e.id));
  const nodesXml = record.entities
    .map((e) => {
      return (
        '    <node id="' +
        escapeXml(e.id) +
        '">\n      <data key="label">' +
        escapeXml(e.name) +
        '</data>\n      <data key="type">' +
        escapeXml(e.type) +
        '</data>\n      <data key="confidence">' +
        escapeXml(e.confidence) +
        '</data>\n    </node>'
      );
    })
    .join('\n');
  const relEdges = record.relationships
    .map((rel) => {
      if (!entityIds.has(rel.sourceId) || !entityIds.has(rel.targetId)) return '';
      return (
        '    <edge id="' +
        escapeXml(rel.id) +
        '" source="' +
        escapeXml(rel.sourceId) +
        '" target="' +
        escapeXml(rel.targetId) +
        '">\n      <data key="edgelabel">' +
        escapeXml(rel.type) +
        '</data>\n    </edge>'
      );
    })
    .filter(Boolean)
    .join('\n');
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n' +
    '  <key id="label" for="node" attr.name="label" attr.type="string"/>\n' +
    '  <key id="type" for="node" attr.name="type" attr.type="string"/>\n' +
    '  <key id="confidence" for="node" attr.name="confidence" attr.type="string"/>\n' +
    '  <key id="edgelabel" for="edge" attr.name="label" attr.type="string"/>\n' +
    '  <graph id="' +
    escapeXml(record.id) +
    '" edgedefault="directed">\n' +
    nodesXml +
    '\n' +
    relEdges +
    '\n  </graph>\n</graphml>\n'
  );
}

export function exportGraphML(
  record: CaseRecord,
  correlationHits: CorrelationHit[] = []
) {
  const xml = buildGraphML(record, correlationHits);
  const blob = new Blob([xml], { type: 'application/graphml+xml' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = sanitizeFilename(record.name) + '.graphml';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export type SherlockHit = {
  site: string;
  url: string;
  status: 'found' | 'not_found' | 'error' | 'unknown';
  httpStatus?: number;
  source: 'sherlock-cli' | 'node-fallback';
};

export type SherlockScanResult = {
  username: string;
  mode: 'sherlock-cli' | 'node-fallback';
  hits: SherlockHit[];
  evidence: import('shared').EvidenceRecord[];
  entities: import('shared').EntityRecord[];
  provenance: import('shared').ProvenanceStep[];
  notes: string[];
};

export type SherlockApiResponse = {
  provider: string;
  scannedAt: string;
  results: SherlockScanResult[];
  summary: { usernames: number; totalFound: number; mode: string };
};

export async function runSherlockScan(usernames: string[]): Promise<SherlockApiResponse> {
  const res = await fetch('/api/scan/sherlock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    if (res.status === 429) {
      const retry = (body as { retryAfterSec?: number }).retryAfterSec
        ?? Number(res.headers.get('Retry-After') || 60);
      throw new Error(
        (body as { message?: string }).message ||
          `Rate limited — wait ${retry}s and try again`
      );
    }
    throw new Error(
      (body as { message?: string }).message ||
        (body as { error?: string }).error ||
        `Scan failed (${res.status})`
    );
  }
  return res.json() as Promise<SherlockApiResponse>;
}

export function mergeScanIntoCase(
  record: CaseRecord,
  results: SherlockScanResult[]
): CaseRecord {
  const next: CaseRecord = {
    ...record,
    entities: [...record.entities],
    evidence: [...record.evidence],
    provenance: [...record.provenance],
    events: [...record.events],
  };
  const now = new Date().toISOString().slice(0, 10);
  for (const result of results) {
    for (const entity of result.entities) {
      if (!next.entities.some((e) => e.id === entity.id)) next.entities.push(entity);
    }
    for (const ev of result.evidence) {
      if (!next.evidence.some((e) => e.id === ev.id)) next.evidence.push(ev);
    }
    for (const p of result.provenance) {
      if (!next.provenance.some((x) => x.id === p.id)) next.provenance.push(p);
    }
    if (result.evidence.length > 0) {
      next.events.push({
        id: `event-sherlock-${result.username}-${Date.now()}`,
        entityId: result.entities[0]?.id ?? '',
        date: now,
        title: `Sherlock scan: ${result.username}`,
        notes: result.notes.join(' | '),
      });
    }
  }
  return next;
}

export type FrameworkTool = {
  id: string;
  name: string;
  description: string;
  url: string;
  urlTemplate?: string;
  flag: string;
  opsec: string;
  providerId?: string;
  inAppReady?: boolean;
};

export type FrameworkCategory = {
  id: string;
  name: string;
  description: string;
  tools: FrameworkTool[];
};

export type FrameworkCatalog = {
  source: string;
  inspiredBy: string;
  note: string;
  categories: FrameworkCategory[];
  providers: {
    id: string;
    name: string;
    category: string;
    envKey: string;
    configured: boolean;
  }[];
  summary: {
    categories: number;
    tools: number;
    providersConfigured: number;
    providersTotal: number;
  };
};

export async function fetchFrameworkCatalog(): Promise<FrameworkCatalog> {
  const res = await fetch('/api/framework');
  if (!res.ok) throw new Error(`Framework catalog failed (${res.status})`);
  return res.json() as Promise<FrameworkCatalog>;
}

export function launchFrameworkTool(tool: FrameworkTool, query: string) {
  const q = encodeURIComponent(query.trim());
  let url = tool.url;
  if (tool.urlTemplate && query.trim()) {
    url = tool.urlTemplate.replace(/\{q\}/g, q);
  }
  if (url.startsWith('/')) return url;
  window.open(url, '_blank', 'noopener,noreferrer');
  return url;
}

export type ProviderLookupResult = {
  provider: string;
  query: string;
  queryType?: string;
  configured?: boolean;
  ok: boolean;
  error?: string;
  hits: Array<string | { title: string; url: string; detail?: string; tags?: string[] }>;
  rawSummary?: string;
  entities: import('shared').EntityRecord[];
  evidence: import('shared').EvidenceRecord[];
  provenance: import('shared').ProvenanceStep[];
};

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 429) {
      const retry =
        (data as { retryAfterSec?: number }).retryAfterSec ??
        Number(res.headers.get('Retry-After') || 60);
      throw new Error(
        (data as { message?: string }).message ||
          `Rate limited — wait ${retry}s and try again`
      );
    }
    throw new Error(
      (data as { message?: string }).message ||
        (data as { error?: string }).error ||
        `Request failed (${res.status})`
    );
  }
  return data as T;
}

export function lookupEmailBundle(email: string) {
  return postJson<{ query: string; scannedAt: string; results: ProviderLookupResult[] }>(
    '/api/scan/email',
    { email }
  );
}

export function lookupHunterDomain(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/hunter/domain', { domain });
}

export function lookupVirusTotalDomain(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/virustotal/domain', { domain });
}

export function lookupShodan(ip: string) {
  return postJson<ProviderLookupResult>('/api/scan/shodan', { ip });
}

export function lookupAbuseIp(ip: string) {
  return postJson<ProviderLookupResult>('/api/scan/abuseipdb', { ip });
}

export function lookupNumverify(phone: string) {
  return postJson<ProviderLookupResult>('/api/scan/numverify', { phone });
}

export function lookupSpiderfoot(target: string) {
  return postJson<ProviderLookupResult & { mode?: string; eventCount?: number; modules?: string[] }>(
    '/api/scan/spiderfoot',
    { target }
  );
}

export function mergeProviderIntoCase(
  record: CaseRecord,
  results: ProviderLookupResult[]
): CaseRecord {
  const next: CaseRecord = {
    ...record,
    entities: [...record.entities],
    evidence: [...record.evidence],
    provenance: [...record.provenance],
    events: [...record.events],
  };
  const now = new Date().toISOString().slice(0, 10);
  for (const result of results) {
    if (!result.ok) continue;
    for (const entity of result.entities) {
      if (!next.entities.some((e) => e.id === entity.id)) next.entities.push(entity);
    }
    for (const ev of result.evidence) {
      if (!next.evidence.some((e) => e.id === ev.id)) next.evidence.push(ev);
    }
    for (const p of result.provenance) {
      if (!next.provenance.some((x) => x.id === p.id)) next.provenance.push(p);
    }
    next.events.push({
      id: `event-${result.provider}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      entityId: result.entities[0]?.id ?? '',
      date: now,
      title: `${result.provider}: ${result.query} (${result.hits.length} hit(s))`,
      notes: result.rawSummary || result.error || (result.hits.length ? '' : 'No hits from provider'),
    });
  }
  next.report = {
    summary: `${next.entities.length} entities, ${next.evidence.length} evidence items from live lookups.`,
    next: 'Corroborate POSSIBLE findings with independent sources before treating as verified.',
  };
  return next;
}

/* ------------------------------------------------------------------ */
/* Persistence — cases survive a page reload                          */
/* ------------------------------------------------------------------ */

const STORAGE_KEY = 'osint-workbench-cases-v1';

export function loadCases(): CaseRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as CaseRecord[]) : [];
  } catch {
    return [];
  }
}

export function saveCases(cases: CaseRecord[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  } catch {
    /* quota exceeded / private mode — ignore */
  }
}

/* ------------------------------------------------------------------ */
/* Case management                                                    */
/* ------------------------------------------------------------------ */

export function renameCase(cases: CaseRecord[], caseId: string, name: string): CaseRecord[] {
  return cases.map((c) => (c.id === caseId ? { ...c, name: name.trim() || c.name } : c));
}

export function deleteCase(cases: CaseRecord[], caseId: string): CaseRecord[] {
  return cases.filter((c) => c.id !== caseId);
}

/* ------------------------------------------------------------------ */
/* Verification workflow — tools never verify; only an analyst can.   */
/* ------------------------------------------------------------------ */

function touchReport(record: CaseRecord): CaseRecord {
  const verifiedEntities = record.entities.filter((e) => e.verified).length;
  const verifiedEvidence = record.evidence.filter((e) => e.verified).length;
  return {
    ...record,
    report: {
      summary: `${record.entities.length} entities (${verifiedEntities} verified), ${record.evidence.length} evidence items (${verifiedEvidence} verified).`,
      next:
        verifiedEntities + verifiedEvidence > 0
          ? 'Verified findings are marked High. Continue corroborating POSSIBLE findings.'
          : 'Corroborate POSSIBLE findings with independent sources before treating as verified.',
    },
  };
}

export function promoteEntityConfidence(record: CaseRecord, entityId: string): CaseRecord {
  return touchReport({
    ...record,
    entities: record.entities.map((e) =>
      e.id === entityId
        ? { ...e, confidence: promoteConfidence(e.confidence), verified: false }
        : e
    ),
  });
}

export function verifyEntity(
  record: CaseRecord,
  entityId: string,
  by = 'analyst'
): CaseRecord {
  const now = new Date().toISOString();
  const target = record.entities.find((e) => e.id === entityId);
  return touchReport({
    ...record,
    entities: record.entities.map((e) =>
      e.id === entityId
        ? { ...e, confidence: 'High' as Confidence, verified: true, verifiedAt: now, verifiedBy: by }
        : e
    ),
    provenance: [
      ...record.provenance,
      {
        id: `prov-verify-${entityId}-${Date.now()}`,
        entityId,
        evidenceId: '',
        claim: `Analyst verified entity "${target?.name ?? entityId}" (confidence set to High).`,
        notes: `Verified by ${by} at ${now}`,
      },
    ],
  });
}

export function unverifyEntity(record: CaseRecord, entityId: string): CaseRecord {
  return touchReport({
    ...record,
    entities: record.entities.map((e) =>
      e.id === entityId
        ? { ...e, confidence: 'Medium' as Confidence, verified: false, verifiedAt: undefined, verifiedBy: undefined }
        : e
    ),
  });
}

export function promoteEvidenceConfidence(record: CaseRecord, evidenceId: string): CaseRecord {
  return touchReport({
    ...record,
    evidence: record.evidence.map((e) =>
      e.id === evidenceId
        ? { ...e, confidence: promoteConfidence(e.confidence), verified: false }
        : e
    ),
  });
}

export function verifyEvidence(
  record: CaseRecord,
  evidenceId: string,
  by = 'analyst'
): CaseRecord {
  const now = new Date().toISOString();
  const target = record.evidence.find((e) => e.id === evidenceId);
  return touchReport({
    ...record,
    evidence: record.evidence.map((e) =>
      e.id === evidenceId
        ? { ...e, confidence: 'High' as Confidence, verified: true, verifiedAt: now, verifiedBy: by }
        : e
    ),
    provenance: [
      ...record.provenance,
      {
        id: `prov-verify-${evidenceId}-${Date.now()}`,
        entityId: target?.entityIds[0] ?? '',
        evidenceId,
        claim: `Analyst verified evidence "${target?.title ?? evidenceId}" (confidence set to High).`,
        notes: `Verified by ${by} at ${now}`,
      },
    ],
  });
}

export function unverifyEvidence(record: CaseRecord, evidenceId: string): CaseRecord {
  return touchReport({
    ...record,
    evidence: record.evidence.map((e) =>
      e.id === evidenceId
        ? { ...e, confidence: 'Medium' as Confidence, verified: false, verifiedAt: undefined, verifiedBy: undefined }
        : e
    ),
  });
}

export function removeEntity(record: CaseRecord, entityId: string): CaseRecord {
  return touchReport({
    ...record,
    entities: record.entities.filter((e) => e.id !== entityId),
    evidence: record.evidence.map((e) => ({
      ...e,
      entityIds: e.entityIds.filter((id) => id !== entityId),
    })),
    provenance: record.provenance.filter((p) => p.entityId !== entityId),
    relationships: record.relationships.filter(
      (r) => r.sourceId !== entityId && r.targetId !== entityId
    ),
  });
}

export function removeEvidence(record: CaseRecord, evidenceId: string): CaseRecord {
  return touchReport({
    ...record,
    evidence: record.evidence.filter((e) => e.id !== evidenceId),
    provenance: record.provenance.filter((p) => p.evidenceId !== evidenceId),
  });
}

export function addRelationship(
  record: CaseRecord,
  sourceId: string,
  targetId: string,
  type: string
): CaseRecord {
  if (!sourceId || !targetId || sourceId === targetId) return record;
  const rel: RelationshipRecord = {
    id: `rel-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    sourceId,
    targetId,
    type: type.trim() || 'related-to',
    confidence: 'Low',
    notes: 'Analyst-linked relationship (POSSIBLE until verified).',
  };
  return { ...record, relationships: [...record.relationships, rel] };
}

export function removeRelationship(record: CaseRecord, relId: string): CaseRecord {
  return { ...record, relationships: record.relationships.filter((r) => r.id !== relId) };
}

/* ------------------------------------------------------------------ */
/* Free recon (no API key)                                            */
/* ------------------------------------------------------------------ */

export type FreeReconResponse = {
  query: string;
  queryType: string;
  scannedAt: string;
  results: ProviderLookupResult[];
};

export function lookupFreeRecon(target: string) {
  return postJson<FreeReconResponse>('/api/scan/free', { target });
}

export function lookupDns(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/dns', { domain });
}

export function lookupRdap(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/rdap', { domain });
}

export function lookupHostSearch(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/hostsearch', { domain });
}

export function lookupCrtSh(domain: string) {
  return postJson<ProviderLookupResult>('/api/scan/crtsh', { domain });
}

export function lookupIpGeo(ip: string) {
  return postJson<ProviderLookupResult>('/api/scan/ipgeo', { ip });
}

export function lookupGravatar(email: string) {
  return postJson<ProviderLookupResult>('/api/scan/gravatar', { email });
}

export function lookupWayback(target: string) {
  return postJson<ProviderLookupResult>('/api/scan/wayback', { target });
}
