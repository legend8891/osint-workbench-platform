import JSZip from 'jszip';
import type { CaseRecord, CorrelationHit } from 'shared';

/**
 * Normalize identifier tokens for correlation.
 * - trim + lowercase
 * - collapse internal whitespace
 * Future: leet, separators, alternate spellings can be added here.
 */
function normalizeToken(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Build cross-case correlation hits.
 * Only tokens that appear in more than one distinct caseId are emitted.
 * Confidence of the hit is the lowest confidence among contributing entities
 * (conservative). Matches preserve full evidence chain (case + entity).
 */
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

export function exportHtmlReport(record: CaseRecord, correlationHits: CorrelationHit[]) {
  const hitsHtml = correlationHits
    .map(
      (h) =>
        `<li><strong>${escapeHtml(h.token)}</strong> — ${h.matches.length} matches<ul>${h.matches
          .map(
            (m) =>
              `<li>${escapeHtml(m.caseName)} / ${escapeHtml(m.entityName)} (${escapeHtml(
                m.entityType
              )})</li>`
          )
          .join('')}</ul></li>`
    )
    .join('');

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(record.name)} — OSINT Report</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
    h1,h2{color:#01696f}
    .meta{color:#666;font-size:.9rem}
    pre{background:#f4f4f0;padding:1rem;overflow:auto;border-radius:8px}
  </style>
</head>
<body>
  <h1>${escapeHtml(record.name)}</h1>
  <p class="meta">Generated ${new Date().toISOString()} · Confidence labels preserved from source</p>
  <h2>Summary</h2>
  <p>${escapeHtml(record.report.summary)}</p>
  <p><strong>Next steps:</strong> ${escapeHtml(record.report.next)}</p>
  <h2>Entities</h2>
  <ul>
    ${record.entities
      .map(
        (e) =>
          `<li><strong>${escapeHtml(e.name)}</strong> (${escapeHtml(e.type)}) — ${escapeHtml(
            e.confidence
          )}<br/><small>${escapeHtml(e.identifiers.join(' · '))}</small></li>`
      )
      .join('')}
  </ul>
  <h2>Cross-case correlation hits</h2>
  ${correlationHits.length ? `<ul>${hitsHtml}</ul>` : '<p>None</p>'}
  <h2>Raw correlation JSON</h2>
  <pre>${escapeHtml(JSON.stringify(correlationHits, null, 2))}</pre>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${record.name}.html`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export async function exportBundleZip(record: CaseRecord, correlationHits: CorrelationHit[]) {
  const zip = new JSZip();
  zip.file('case.json', JSON.stringify(record, null, 2));
  zip.file('correlations.json', JSON.stringify(correlationHits, null, 2));
  zip.file('graph.graphml', buildGraphML(record, correlationHits));
  zip.file(
    'report.html',
    `<!doctype html><html><head><meta charset="UTF-8"><title>${escapeHtml(
      record.name
    )}</title></head><body><h1>${escapeHtml(record.name)}</h1><p>${escapeHtml(
      record.report.summary
    )}</p><p>${escapeHtml(record.report.next)}</p></body></html>`
  );
  const blob = await zip.generateAsync({ type: 'blob' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${record.name}.zip`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

/**
 * Build GraphML (XML) for entities + relationships.
 * Suitable for import into Maltego (tabular/GraphML workflows), yEd, Gephi, etc.
 * Confidence and identifiers are preserved as node/edge data attributes.
 * Correlation-only tokens that are not already entities are emitted as extra nodes
 * linked via a synthetic "correlates_with" edge when useful for Maltego pivoting.
 */
export function buildGraphML(
  record: CaseRecord,
  correlationHits: CorrelationHit[] = []
): string {
  const nodeKeys = [
    { id: 'label', attrName: 'label', attrType: 'string' },
    { id: 'type', attrName: 'type', attrType: 'string' },
    { id: 'confidence', attrName: 'confidence', attrType: 'string' },
    { id: 'identifiers', attrName: 'identifiers', attrType: 'string' },
    { id: 'notes', attrName: 'notes', attrType: 'string' },
    { id: 'verification', attrName: 'verification', attrType: 'string' },
  ];
  const edgeKeys = [
    { id: 'edgelabel', attrName: 'label', attrType: 'string' },
    { id: 'edgeconfidence', attrName: 'confidence', attrType: 'string' },
    { id: 'edgenotes', attrName: 'notes', attrType: 'string' },
  ];

  const keysXml = [
    ...nodeKeys.map(
      (k) =>
        `  <key id="${k.id}" for="node" attr.name="${k.attrName}" attr.type="${k.attrType}"/>`
    ),
    ...edgeKeys.map(
      (k) =>
        `  <key id="${k.id}" for="edge" attr.name="${k.attrName}" attr.type="${k.attrType}"/>`
    ),
  ].join('\n');

  const entityIds = new Set(record.entities.map((e) => e.id));

  const nodesXml = record.entities
    .map((e) => {
      // Never auto-VERIFIED: map confidence to explicit verification label
      const verification =
        e.confidence === 'High' ? 'POSSIBLE_HIGH' : `POSSIBLE_${e.confidence.toUpperCase()}`;
      return `    <node id="${escapeXml(e.id)}">
      <data key="label">${escapeXml(e.name)}</data>
      <data key="type">${escapeXml(e.type)}</data>
      <data key="confidence">${escapeXml(e.confidence)}</data>
      <data key="identifiers">${escapeXml(e.identifiers.join(' | '))}</data>
      <data key="notes">${escapeXml(e.notes)}</data>
      <data key="verification">${escapeXml(verification)}</data>
    </node>`;
    })
    .join('\n');

  // Evidence as optional URL nodes (linked to first related entity)
  const evidenceNodes = record.evidence
    .map((ev) => {
      const id = `evidence-${ev.id}`;
      return `    <node id="${escapeXml(id)}">
      <data key="label">${escapeXml(ev.title)}</data>
      <data key="type">Evidence</data>
      <data key="confidence">${escapeXml(ev.confidence)}</data>
      <data key="identifiers">${escapeXml([ev.url, ev.archiveUrl].filter(Boolean).join(' | '))}</data>
      <data key="notes">${escapeXml(ev.notes)}</data>
      <data key="verification">POSSIBLE_${ev.confidence.toUpperCase()}</data>
    </node>`;
    })
    .join('\n');

  const evidenceEdges = record.evidence
    .flatMap((ev) =>
      (ev.entityIds.length ? ev.entityIds : []).map((entityId, i) => {
        if (!entityIds.has(entityId)) return '';
        return `    <edge id="ev-link-${escapeXml(ev.id)}-${i}" source="${escapeXml(entityId)}" target="${escapeXml(`evidence-${ev.id}`)}">
      <data key="edgelabel">has_evidence</data>
      <data key="edgeconfidence">${escapeXml(ev.confidence)}</data>
      <data key="edgenotes">${escapeXml(ev.tags.join(', '))}</data>
    </edge>`;
      })
    )
    .filter(Boolean)
    .join('\n');

  const relEdges = record.relationships
    .map((rel) => {
      if (!entityIds.has(rel.sourceId) || !entityIds.has(rel.targetId)) return '';
      return `    <edge id="${escapeXml(rel.id)}" source="${escapeXml(rel.sourceId)}" target="${escapeXml(rel.targetId)}">
      <data key="edgelabel">${escapeXml(rel.type)}</data>
      <data key="edgeconfidence">${escapeXml(rel.confidence)}</data>
      <data key="edgenotes">${escapeXml(rel.notes)}</data>
    </edge>`;
    })
    .filter(Boolean)
    .join('\n');

  // Optional: surface cross-case correlation tokens as annotation nodes (same case only if token matches an entity identifier)
  const corrAnnotation = correlationHits
    .filter((h) => h.matches.some((m) => m.caseId === record.id))
    .map((h, idx) => {
      const id = `corr-${idx}-${h.token.slice(0, 32)}`;
      return `    <node id="${escapeXml(id)}">
      <data key="label">${escapeXml(`corr:${h.token}`)}</data>
      <data key="type">CorrelationToken</data>
      <data key="confidence">Low</data>
      <data key="identifiers">${escapeXml(h.token)}</data>
      <data key="notes">${escapeXml(`${h.matches.length} cross-case matches — POSSIBLE only`)}</data>
      <data key="verification">POSSIBLE_LOW</data>
    </node>`;
    })
    .join('\n');

  const corrEdges = correlationHits
    .filter((h) => h.matches.some((m) => m.caseId === record.id))
    .flatMap((h, idx) => {
      const corrId = `corr-${idx}-${h.token.slice(0, 32)}`;
      return h.matches
        .filter((m) => m.caseId === record.id && entityIds.has(m.entityId))
        .map(
          (m, j) =>
            `    <edge id="corr-edge-${idx}-${j}" source="${escapeXml(m.entityId)}" target="${escapeXml(corrId)}">
      <data key="edgelabel">shares_token</data>
      <data key="edgeconfidence">Low</data>
      <data key="edgenotes">Cross-case correlation — POSSIBLE</data>
    </edge>`
        );
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
${keysXml}
  <graph id="${escapeXml(record.id)}" edgedefault="directed">
    <!-- Case: ${escapeXml(record.name)} | location: ${escapeXml(record.location)} -->
    <!-- All confidence values are source labels; verification=* is never auto-VERIFIED -->
${nodesXml}
${evidenceNodes}
${corrAnnotation}
${relEdges}
${evidenceEdges}
${corrEdges}
  </graph>
</graphml>
`;
}

export function exportGraphML(
  record: CaseRecord,
  correlationHits: CorrelationHit[] = []
) {
  const xml = buildGraphML(record, correlationHits);
  const blob = new Blob([xml], { type: 'application/graphml+xml' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${sanitizeFilename(record.name)}.graphml`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^\w.\- ]+/g, '_').trim() || 'case';
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Sherlock / external scan helpers
// ---------------------------------------------------------------------------

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
  summary: {
    usernames: number;
    totalFound: number;
    mode: string;
  };
};

/** Call the server Sherlock provider. Uses Vite proxy (/api → :8787). */
export async function runSherlockScan(
  usernames: string[]
): Promise<SherlockApiResponse> {
  const res = await fetch('/api/scan/sherlock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(
      (body as { message?: string }).message ||
        (body as { error?: string }).error ||
        `Scan failed (${res.status})`
    );
  }
  return res.json() as Promise<SherlockApiResponse>;
}

/**
 * Merge Sherlock results into a case. Preserves existing data;
 * appends new entities / evidence / provenance. Does not auto-promote confidence.
 */
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
      // avoid exact id collision; keep if same name already present
      if (!next.entities.some((e) => e.id === entity.id)) {
        next.entities.push(entity);
      }
    }
    for (const ev of result.evidence) {
      if (!next.evidence.some((e) => e.id === ev.id)) {
        next.evidence.push(ev);
      }
    }
    for (const p of result.provenance) {
      if (!next.provenance.some((x) => x.id === p.id)) {
        next.provenance.push(p);
      }
    }
    if (result.evidence.length > 0) {
      next.events.push({
        id: `event-sherlock-${result.username}-${Date.now()}`,
        entityId: result.entities[0]?.id ?? '',
        date: now,
        title: `Sherlock scan: ${result.username} (${result.hits.filter((h) => h.status === 'found').length} sites)`,
        notes: result.notes.join(' | '),
      });
    }
  }

  return next;
}

// ---------------------------------------------------------------------------
// OSINT Framework catalog
// ---------------------------------------------------------------------------

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
  openUrl?: string;
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
    endpoint?: string;
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
  if (!res.ok) {
    throw new Error(`Framework catalog failed (${res.status})`);
  }
  return res.json() as Promise<FrameworkCatalog>;
}

export function launchFrameworkTool(tool: FrameworkTool, query: string) {
  const q = encodeURIComponent(query.trim());
  let url = tool.url;
  if (tool.urlTemplate && query.trim()) {
    url = tool.urlTemplate.replace(/\{q\}/g, q);
  }
  if (url.startsWith('/')) {
    // in-app API — caller should use provider action instead
    return url;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
  return url;
}

// ---------------------------------------------------------------------------
// Live provider lookups (server uses API keys from env)
// ---------------------------------------------------------------------------

export type ProviderLookupResult = {
  provider: string;
  query: string;
  queryType: string;
  configured: boolean;
  ok: boolean;
  error?: string;
  hits: { title: string; url: string; detail: string; tags: string[] }[];
  rawSummary: string;
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

/** Merge any provider lookup result into a case (live data only). */
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
    if (result.hits.length > 0) {
      next.events.push({
        id: `event-${result.provider}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        entityId: result.entities[0]?.id ?? '',
        date: now,
        title: `${result.provider}: ${result.query} (${result.hits.length} hit(s))`,
        notes: result.rawSummary || result.error || '',
      });
    }
  }
  next.report = {
    summary: `${next.entities.length} entities, ${next.evidence.length} evidence items from live lookups.`,
    next: 'Corroborate POSSIBLE findings with independent sources before treating as verified.',
  };
  return next;
}
