import JSZip from 'jszip';
import type {
  CaseRecord,
  CorrelationHit,
  Confidence,
  EntityRecord,
  EvidenceRecord,
  RelationshipRecord,
} from 'shared';
import { promoteConfidence, caseSchema } from 'shared';
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

export function sanitizeFilename(name: string): string {
  return name.replace(/[^\w.\- ]+/g, '_').trim() || 'case';
}

export function exportHtmlReport(record: CaseRecord, correlationHits: CorrelationHit[]) {
  const badge = (confidence: string, verified?: boolean) =>
    '<span class="badge badge-' +
    escapeHtml(confidence.toLowerCase()) +
    '">' +
    escapeHtml(confidence) +
    (verified ? ' &#10003;' : '') +
    '</span>';

  const section = (title: string, inner: string) =>
    '<section><h2>' + escapeHtml(title) + '</h2>' + inner + '</section>';

  const entitiesHtml = record.entities.length
    ? '<ul class="cards">' +
      record.entities
        .map(
          (e) =>
            '<li><strong>' +
            escapeHtml(e.name) +
            '</strong> <em>(' +
            escapeHtml(e.type) +
            ')</em> ' +
            badge(e.confidence, e.verified) +
            (e.identifiers.length
              ? '<div class="muted">' + escapeHtml(e.identifiers.join(' · ')) + '</div>'
              : '') +
            (e.notes ? '<div class="muted">' + escapeHtml(e.notes) + '</div>' : '') +
            (e.verified && e.verifiedBy
              ? '<div class="muted">Verified by ' +
                escapeHtml(e.verifiedBy) +
                (e.verifiedAt ? ' · ' + escapeHtml(new Date(e.verifiedAt).toLocaleString()) : '') +
                '</div>'
              : '') +
            '</li>'
        )
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const evidenceHtml = record.evidence.length
    ? '<ul class="cards">' +
      record.evidence
        .map(
          (ev) =>
            '<li><strong>' +
            escapeHtml(ev.title) +
            '</strong> ' +
            badge(ev.confidence, ev.verified) +
            (ev.url
              ? '<div><a href="' + escapeHtml(ev.url) + '">' + escapeHtml(ev.url) + '</a></div>'
              : '') +
            (ev.notes ? '<div class="muted">' + escapeHtml(ev.notes) + '</div>' : '') +
            (ev.tags.length
              ? '<div class="muted">' + escapeHtml(ev.tags.join(', ')) + '</div>'
              : '') +
            '</li>'
        )
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const entityName = (id: string) =>
    record.entities.find((e) => e.id === id)?.name ?? id;
  const relationshipsHtml = record.relationships.length
    ? '<ul class="cards">' +
      record.relationships
        .map(
          (rel) =>
            '<li>' +
            escapeHtml(entityName(rel.sourceId)) +
            ' &rarr; ' +
            escapeHtml(entityName(rel.targetId)) +
            ' <em>(' +
            escapeHtml(rel.type) +
            ')</em> ' +
            badge(rel.confidence) +
            '</li>'
        )
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const timelineHtml = record.events.length
    ? '<ul class="cards">' +
      record.events
        .map(
          (ev) =>
            '<li><strong>' +
            escapeHtml(ev.date) +
            '</strong> — ' +
            escapeHtml(ev.title) +
            (ev.notes ? '<div class="muted">' + escapeHtml(ev.notes) + '</div>' : '') +
            '</li>'
        )
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const provenanceHtml = record.provenance.length
    ? '<ul class="cards">' +
      record.provenance
        .map(
          (p) =>
            '<li>' +
            escapeHtml(p.claim) +
            (p.notes ? '<div class="muted">' + escapeHtml(p.notes) + '</div>' : '') +
            '</li>'
        )
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const hitsHtml = correlationHits.length
    ? '<ul class="cards">' +
      correlationHits
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
        .join('') +
      '</ul>'
    : '<p class="muted">None</p>';

  const style =
    'body{font-family:Inter,system-ui,-apple-system,sans-serif;color:#28251d;background:#fff;max-width:52rem;margin:0 auto;padding:2rem;line-height:1.5}' +
    'h1{margin-bottom:.25rem}h2{border-bottom:1px solid #ddd;padding-bottom:.25rem;margin-top:1.5rem}' +
    '.muted{color:#6f6d68;font-size:.85rem}.cards{list-style:none;padding:0;display:grid;gap:.5rem}' +
    '.cards li{border:1px solid #e2e0da;border-radius:10px;padding:.6rem .8rem}' +
    '.badge{display:inline-block;padding:.05rem .5rem;border-radius:999px;font-size:.7rem;font-weight:600;color:#fff;background:#6f6d68}' +
    '.badge-high{background:#1c7c54}.badge-medium{background:#a15c00}.badge-low{background:#6f6d68}.badge-unverified{background:#8a6d3b}' +
    'a{color:#01696f;word-break:break-all}' +
    '@media print{body{padding:0}.cards li{break-inside:avoid}}';

  const html =
    '<!doctype html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' +
    escapeHtml(record.name) +
    ' — OSINT Report</title><style>' +
    style +
    '</style></head><body>' +
    '<h1>' +
    escapeHtml(record.name) +
    '</h1>' +
    '<p class="muted">' +
    escapeHtml(record.type) +
    (record.location ? ' · ' + escapeHtml(record.location) : '') +
    ' · generated ' +
    escapeHtml(new Date().toLocaleString()) +
    '</p>' +
    '<p>' +
    escapeHtml(record.report.summary) +
    '</p><p>' +
    escapeHtml(record.report.next) +
    '</p>' +
    section('Entities', entitiesHtml) +
    section('Evidence', evidenceHtml) +
    section('Relationships', relationshipsHtml) +
    section('Timeline', timelineHtml) +
    section('Provenance', provenanceHtml) +
    section('Cross-case correlation', hitsHtml) +
    '</body></html>';

  const blob = new Blob([html], { type: 'text/html' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = sanitizeFilename(record.name) + '.html';
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
  link.download = sanitizeFilename(record.name) + '.zip';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export function buildGraphML(
  record: CaseRecord,
  correlationHits: CorrelationHit[] = []
): string {
  const entityIds = new Set(record.entities.map((e) => e.id));
  // Map entityId -> cross-case tokens it participates in (this case only).
  const corrByEntity = new Map<string, string[]>();
  for (const hit of correlationHits) {
    for (const m of hit.matches) {
      if (m.caseId !== record.id) continue;
      const list = corrByEntity.get(m.entityId) ?? [];
      list.push(hit.token);
      corrByEntity.set(m.entityId, list);
    }
  }
  const nodesXml = record.entities
    .map((e) => {
      const corr = corrByEntity.get(e.id);
      const corrXml = corr?.length
        ? '\n      <data key="correlation">' + escapeXml([...new Set(corr)].join(', ')) + '</data>'
        : '';
      return (
        '    <node id="' +
        escapeXml(e.id) +
        '">\n      <data key="label">' +
        escapeXml(e.name) +
        '</data>\n      <data key="type">' +
        escapeXml(e.type) +
        '</data>\n      <data key="confidence">' +
        escapeXml(e.confidence) +
        '</data>' +
        corrXml +
        '\n    </node>'
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
    '  <key id="correlation" for="node" attr.name="correlation" attr.type="string"/>\n' +
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

/** Stable identity for an entity: type + normalised name. */
function entityKey(e: { type: string; name: string }): string {
  return `${e.type.toLowerCase()}|${e.name.trim().toLowerCase()}`;
}

/** Merge incoming entities into a list, de-duplicating by type+name and
 *  unioning identifiers so re-running a lookup enriches instead of duplicating. */
function mergeEntityList(existing: EntityRecord[], incoming: EntityRecord[]): EntityRecord[] {
  const out = [...existing];
  for (const ent of incoming) {
    const key = entityKey(ent);
    const idx = out.findIndex((e) => entityKey(e) === key);
    if (idx === -1) {
      out.push(ent);
      continue;
    }
    const prev = out[idx];
    out[idx] = {
      ...prev,
      identifiers: [...new Set([...prev.identifiers, ...ent.identifiers])],
      notes: prev.notes.length >= ent.notes.length ? prev.notes : ent.notes,
      // never downgrade an analyst-verified entity
      confidence: prev.verified ? prev.confidence : prev.confidence,
      verified: prev.verified,
      verifiedAt: prev.verifiedAt,
      verifiedBy: prev.verifiedBy,
    };
  }
  return out;
}

/** Merge evidence, de-duplicating by title+url. */
function mergeEvidenceList(existing: EvidenceRecord[], incoming: EvidenceRecord[]): EvidenceRecord[] {
  const out = [...existing];
  for (const ev of incoming) {
    if (!out.some((e) => e.title === ev.title && e.url === ev.url)) out.push(ev);
  }
  return out;
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
    next.entities = mergeEntityList(next.entities, result.entities);
    next.evidence = mergeEvidenceList(next.evidence, result.evidence);
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
    next.entities = mergeEntityList(next.entities, result.entities);
    next.evidence = mergeEvidenceList(next.evidence, result.evidence);
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

export function saveCases(cases: CaseRecord[]): boolean {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
    return true;
  } catch {
    /* quota exceeded / private mode */
    return false;
  }
}

/** Parse + validate an exported case JSON file. Throws with a readable message. */
export function parseImportedCase(raw: string): CaseRecord {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error('Not valid JSON.');
  }
  const parsed = caseSchema.safeParse(data);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .slice(0, 3)
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    throw new Error(`Invalid case file — ${detail}`);
  }
  return parsed.data as CaseRecord;
}

/** Ensure an imported case has a unique id within the existing set. */
export function withUniqueId(record: CaseRecord, existing: CaseRecord[]): CaseRecord {
  if (!existing.some((c) => c.id === record.id)) return record;
  return { ...record, id: `${record.id}-${Date.now().toString(36)}` };
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
        ? {
            ...e,
            confidence: promoteConfidence(e.confidence),
            verified: false,
            verifiedAt: undefined,
            verifiedBy: undefined,
          }
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
  // Idempotent: re-verifying must not append duplicate provenance.
  if (target?.verified) return record;
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
        ? {
            ...e,
            confidence: promoteConfidence(e.confidence),
            verified: false,
            verifiedAt: undefined,
            verifiedBy: undefined,
          }
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
  // Idempotent: re-verifying must not append duplicate provenance.
  if (target?.verified) return record;
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

export function lookupInternetDb(ip: string) {
  return postJson<ProviderLookupResult>('/api/scan/internetdb', { ip });
}

export function lookupIpRdap(ip: string) {
  return postJson<ProviderLookupResult>('/api/scan/iprdap', { ip });
}

export function lookupGravatar(email: string) {
  return postJson<ProviderLookupResult>('/api/scan/gravatar', { email });
}

export function lookupWayback(target: string) {
  return postJson<ProviderLookupResult>('/api/scan/wayback', { target });
}
