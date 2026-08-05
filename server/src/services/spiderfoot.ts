/**
 * SpiderFoot CLI integration (Path B).
 * Runs local SpiderFoot if installed; maps events → entities/evidence/provenance.
 *
 * Env:
 *   SPIDERFOOT_BIN     – path to spiderfoot / sf / sf.py (optional auto-detect)
 *   SPIDERFOOT_TIMEOUT_MS – max run time (default 180000)
 *   SPIDERFOOT_MAX_EVENTS – cap events mapped (default 200)
 *
 * Install (on a VPS/Docker host, not ideal on free Render):
 *   pip install spiderfoot
 *   # or git clone https://github.com/smicallef/spiderfoot
 */

import { spawn } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import { randomUUID } from 'node:crypto';

export type SfConfidence = 'High' | 'Medium' | 'Low' | 'Unverified';

export interface SfEntity {
  id: string;
  name: string;
  type: string;
  identifiers: string[];
  confidence: SfConfidence;
  notes: string;
}

export interface SfEvidence {
  id: string;
  title: string;
  url: string;
  archiveUrl: string;
  tags: string[];
  confidence: SfConfidence;
  entityIds: string[];
  notes: string;
  eventDate: string;
  date: string;
  attachments: { name: string; type: string; dataUrl: string }[];
}

export interface SfProvenance {
  id: string;
  entityId: string;
  evidenceId: string;
  claim: string;
  notes: string;
}

export interface SfHit {
  title: string;
  url: string;
  detail: string;
  tags: string[];
}

export interface SpiderFootScanResult {
  provider: 'spiderfoot';
  query: string;
  queryType: string;
  configured: boolean;
  ok: boolean;
  error?: string;
  mode: 'cli' | 'unavailable';
  binary?: string;
  hits: SfHit[];
  rawSummary: string;
  entities: SfEntity[];
  evidence: SfEvidence[];
  provenance: SfProvenance[];
  eventCount: number;
  modules: string[];
}

function id(prefix: string) {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function executable(path: string): boolean {
  try {
    accessSync(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveSpiderfootBin(): string | null {
  const fromEnv = process.env.SPIDERFOOT_BIN?.trim();
  if (fromEnv && executable(fromEnv)) return fromEnv;
  const candidates = [
    'spiderfoot',
    'sf',
    '/usr/local/bin/spiderfoot',
    '/usr/bin/spiderfoot',
    '/opt/spiderfoot/sf.py',
    '/app/spiderfoot/sf.py',
  ];
  for (const c of candidates) {
    if (c.includes('/') && executable(c)) return c;
  }
  return fromEnv || 'spiderfoot';
}

function inferQueryType(target: string): string {
  const t = target.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return 'email';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return 'ip';
  if (/^\+?\d{8,15}$/.test(t.replace(/[\s()-]/g, ''))) return 'phone';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t) && !t.includes(' ')) return 'domain';
  return 'username';
}

function mapEventTypeToEntityType(sfType: string): string {
  const t = sfType.toUpperCase();
  if (t.includes('EMAIL')) return 'email';
  if (t.includes('IP_ADDRESS') || t === 'IPV4_ADDRESS' || t === 'IPV6_ADDRESS') return 'ip';
  if (t.includes('PHONE') || t.includes('TEL')) return 'phone';
  if (t.includes('HUMAN') || t.includes('PERSON') || t.includes('USERNAME')) return 'person';
  if (t.includes('INTERNET_NAME') || t.includes('DOMAIN') || t.includes('HOSTNAME')) return 'domain';
  if (t.includes('URL') || t.includes('LINK')) return 'url';
  if (t.includes('BTC') || t.includes('BITCOIN')) return 'crypto';
  return 'other';
}

type RawEvent = {
  type?: string;
  data?: string;
  module?: string;
  source?: string;
  confidence?: number | string;
  hash?: string;
};

function parseSpiderfootOutput(stdout: string): RawEvent[] {
  const text = stdout.trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed as RawEvent[];
    if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { events?: unknown }).events)) {
      return (parsed as { events: RawEvent[] }).events;
    }
  } catch {
    /* line-delimited */
  }
  const events: RawEvent[] = [];
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || !l.startsWith('{')) continue;
    try {
      events.push(JSON.parse(l) as RawEvent);
    } catch {
      /* skip */
    }
  }
  return events;
}

function runCli(
  bin: string,
  args: string[],
  timeoutMs: number
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 3000);
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += String(d);
      if (stdout.length > 5_000_000) child.kill('SIGTERM');
    });
    child.stderr.on('data', (d) => {
      stderr += String(d);
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: err.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

export async function runSpiderfootScan(target: string): Promise<SpiderFootScanResult> {
  const query = target.trim();
  const queryType = inferQueryType(query);
  const timeoutMs = Number(process.env.SPIDERFOOT_TIMEOUT_MS) || 180_000;
  const maxEvents = Number(process.env.SPIDERFOOT_MAX_EVENTS) || 200;
  const bin = resolveSpiderfootBin() || 'spiderfoot';

  const argSets: string[][] = [
    ['-s', query, '-o', 'json', '-q'],
    ['-s', query, '-o', 'json'],
  ];

  let lastErr = '';
  let stdout = '';
  let usedBin = bin;
  let ran = false;

  for (const args of argSets) {
    const result = await runCli(bin, args, timeoutMs);
    ran = true;
    if (result.code === null && /ENOENT|not found/i.test(result.stderr)) {
      return {
        provider: 'spiderfoot',
        query,
        queryType,
        configured: false,
        ok: false,
        mode: 'unavailable',
        error:
          'SpiderFoot CLI not found on this host. Install on a VPS/Docker (pip install spiderfoot or clone smicallef/spiderfoot) and set SPIDERFOOT_BIN. Free Render is a poor fit for long SF scans.',
        hits: [],
        rawSummary: 'SpiderFoot unavailable',
        entities: [],
        evidence: [],
        provenance: [],
        eventCount: 0,
        modules: [],
      };
    }
    if (result.stdout.trim()) {
      stdout = result.stdout;
      lastErr = result.stderr;
      break;
    }
    lastErr = result.stderr || `exit ${result.code}`;
  }

  if (!stdout.trim()) {
    return {
      provider: 'spiderfoot',
      query,
      queryType,
      configured: ran,
      ok: false,
      mode: 'cli',
      binary: usedBin,
      error: `SpiderFoot produced no JSON output. ${lastErr.slice(0, 400) || 'Check SPIDERFOOT_BIN and that modules can run headless.'}`,
      hits: [],
      rawSummary: 'No output',
      entities: [],
      evidence: [],
      provenance: [],
      eventCount: 0,
      modules: [],
    };
  }

  const events = parseSpiderfootOutput(stdout).slice(0, maxEvents);
  if (events.length === 0) {
    return {
      provider: 'spiderfoot',
      query,
      queryType,
      configured: true,
      ok: true,
      mode: 'cli',
      binary: usedBin,
      hits: [],
      rawSummary: 'SpiderFoot finished with 0 parseable events.',
      entities: [
        {
          id: id('ent'),
          name: query,
          type: queryType,
          identifiers: [query],
          confidence: 'Low',
          notes: 'SpiderFoot scan completed — no events mapped',
        },
      ],
      evidence: [],
      provenance: [],
      eventCount: 0,
      modules: [],
    };
  }

  const modules = [...new Set(events.map((e) => String(e.module || '')).filter(Boolean))];
  const entities: SfEntity[] = [];
  const evidence: SfEvidence[] = [];
  const provenance: SfProvenance[] = [];
  const hits: SfHit[] = [];
  const entityByKey = new Map<string, SfEntity>();

  const rootKey = `${queryType}:${query.toLowerCase()}`;
  const root: SfEntity = {
    id: id('ent'),
    name: query,
    type: queryType,
    identifiers: [query],
    confidence: 'Low',
    notes: `SpiderFoot target (${events.length} events)`,
  };
  entityByKey.set(rootKey, root);
  entities.push(root);

  for (const ev of events) {
    const data = String(ev.data || '').trim();
    if (!data) continue;
    const sfType = String(ev.type || 'UNKNOWN');
    const mod = String(ev.module || 'spiderfoot');
    const entType = mapEventTypeToEntityType(sfType);
    const key = `${entType}:${data.toLowerCase()}`;

    let entity = entityByKey.get(key);
    if (!entity) {
      entity = {
        id: id('ent'),
        name: data.length > 120 ? data.slice(0, 117) + '…' : data,
        type: entType,
        identifiers: [data],
        confidence: 'Low',
        notes: `SpiderFoot ${sfType} via ${mod}`,
      };
      entityByKey.set(key, entity);
      entities.push(entity);
    }

    const isUrl = /^https?:\/\//i.test(data);
    const evRow: SfEvidence = {
      id: id('ev'),
      title: `${sfType}: ${data.length > 80 ? data.slice(0, 77) + '…' : data}`,
      url: isUrl ? data : '',
      archiveUrl: isUrl ? `https://web.archive.org/web/*/${data}` : '',
      tags: ['spiderfoot', sfType.toLowerCase(), mod.toLowerCase()],
      confidence: 'Low',
      entityIds: [entity.id, root.id],
      notes: `module=${mod}; source=${ev.source || ''}`,
      eventDate: today(),
      date: today(),
      attachments: [],
    };
    evidence.push(evRow);
    provenance.push({
      id: id('prov'),
      entityId: entity.id,
      evidenceId: evRow.id,
      claim: `SpiderFoot module ${mod} emitted ${sfType}=${data}`,
      notes: 'SpiderFoot CLI',
    });
    hits.push({
      title: `${sfType}: ${data.length > 60 ? data.slice(0, 57) + '…' : data}`,
      url: isUrl ? data : '',
      detail: mod,
      tags: ['spiderfoot', sfType.toLowerCase()],
    });
  }

  const cappedEvidence = evidence.slice(0, maxEvents);
  const cappedHits = hits.slice(0, 80);

  return {
    provider: 'spiderfoot',
    query,
    queryType,
    configured: true,
    ok: true,
    mode: 'cli',
    binary: usedBin,
    hits: cappedHits,
    rawSummary: `SpiderFoot: ${events.length} event(s), ${entities.length} entities, modules=${modules.slice(0, 12).join(',') || 'n/a'}`,
    entities: entities.slice(0, 150),
    evidence: cappedEvidence,
    provenance: provenance.slice(0, maxEvents),
    eventCount: events.length,
    modules,
  };
}
