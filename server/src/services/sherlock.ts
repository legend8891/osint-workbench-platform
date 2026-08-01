import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type {
  Confidence,
  EntityRecord,
  EvidenceRecord,
  ProvenanceStep,
} from 'shared';

const execFileAsync = promisify(execFile);

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
  evidence: EvidenceRecord[];
  entities: EntityRecord[];
  provenance: ProvenanceStep[];
  notes: string[];
};

const USERNAME_RE = /^[a-zA-Z0-9._-]{1,39}$/;

const FALLBACK_SITES: {
  name: string;
  url: (u: string) => string;
  exists: (status: number, body: string) => boolean;
}[] = [
  {
    name: 'GitHub',
    url: (u) => `https://github.com/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: 'GitLab',
    url: (u) => `https://gitlab.com/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: 'Reddit',
    url: (u) => `https://www.reddit.com/user/${encodeURIComponent(u)}`,
    exists: (s, body) => s === 200 && !/nobody on Reddit goes by that name/i.test(body),
  },
  {
    name: 'HackerNews',
    url: (u) => `https://news.ycombinator.com/user?id=${encodeURIComponent(u)}`,
    exists: (s, body) => s === 200 && !/No such user/i.test(body),
  },
  {
    name: 'Keybase',
    url: (u) => `https://keybase.io/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: 'Dev.to',
    url: (u) => `https://dev.to/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: 'About.me',
    url: (u) => `https://about.me/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: 'Linktree',
    url: (u) => `https://linktr.ee/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
];

function sanitizeUsername(raw: string): string | null {
  const u = raw.trim().replace(/^@/, '');
  if (!USERNAME_RE.test(u)) return null;
  return u;
}

async function isSherlockCliAvailable(): Promise<boolean> {
  try {
    await execFileAsync('sherlock', ['--version'], { timeout: 5000 });
    return true;
  } catch {
    try {
      await execFileAsync('python3', ['-m', 'sherlock_project', '--version'], {
        timeout: 5000,
      });
      return true;
    } catch {
      return false;
    }
  }
}

function parseSherlockStdout(stdout: string): SherlockHit[] {
  const hits: SherlockHit[] = [];
  const lines = stdout.split(/\r?\n/);
  for (const line of lines) {
    const found = line.match(/\[\+\]\s+([^:]+):\s+(https?:\/\/\S+)/i);
    if (found) {
      hits.push({
        site: found[1].trim(),
        url: found[2].trim(),
        status: 'found',
        source: 'sherlock-cli',
      });
      continue;
    }
    const notFound = line.match(/\[\-\]\s+([^:]+):/i);
    if (notFound) {
      hits.push({
        site: notFound[1].trim(),
        url: '',
        status: 'not_found',
        source: 'sherlock-cli',
      });
    }
  }
  return hits;
}

async function runSherlockCli(username: string): Promise<SherlockHit[]> {
  const args = [username, '--print-found', '--no-color', '--timeout', '10'];
  let stdout = '';
  try {
    const r = await execFileAsync('sherlock', args, {
      timeout: 120_000,
      maxBuffer: 2 * 1024 * 1024,
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    stdout = r.stdout + '\n' + (r.stderr || '');
  } catch (err: unknown) {
    try {
      const r = await execFileAsync(
        'python3',
        ['-m', 'sherlock_project', ...args],
        {
          timeout: 120_000,
          maxBuffer: 2 * 1024 * 1024,
          env: { ...process.env, PYTHONUNBUFFERED: '1' },
        }
      );
      stdout = r.stdout + '\n' + (r.stderr || '');
    } catch (err2: unknown) {
      const e = err2 as { stdout?: string; stderr?: string };
      stdout = (e.stdout || '') + '\n' + (e.stderr || '');
      if (!stdout.trim()) throw err;
    }
  }
  return parseSherlockStdout(stdout);
}

async function runNodeFallback(username: string): Promise<SherlockHit[]> {
  const hits: SherlockHit[] = [];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);

  await Promise.allSettled(
    FALLBACK_SITES.map(async (site) => {
      const url = site.url(username);
      try {
        const res = await fetch(url, {
          method: 'GET',
          redirect: 'follow',
          signal: controller.signal,
          headers: {
            'User-Agent':
              'OSINT-Workbench/0.6 (research; +https://localhost; respectful)',
            Accept: 'text/html,application/xhtml+xml',
          },
        });
        const body = await res.text().catch(() => '');
        const exists = site.exists(res.status, body);
        hits.push({
          site: site.name,
          url: exists ? url : '',
          status: exists ? 'found' : 'not_found',
          httpStatus: res.status,
          source: 'node-fallback',
        });
      } catch {
        hits.push({
          site: site.name,
          url: '',
          status: 'error',
          source: 'node-fallback',
        });
      }
    })
  );

  clearTimeout(timer);
  return hits;
}

function toEvidenceAndEntities(
  username: string,
  hits: SherlockHit[],
  mode: SherlockScanResult['mode']
): Pick<SherlockScanResult, 'evidence' | 'entities' | 'provenance'> {
  const now = new Date().toISOString().slice(0, 10);
  const found = hits.filter((h) => h.status === 'found' && h.url);

  const confidence: Confidence =
    mode === 'sherlock-cli' && found.length >= 3
      ? 'Medium'
      : found.length >= 1
        ? 'Low'
        : 'Unverified';

  const entityId = `entity-sherlock-${username}-${randomUUID().slice(0, 8)}`;
  const entity: EntityRecord = {
    id: entityId,
    name: username,
    type: 'Username',
    confidence,
    identifiers: [username, ...found.map((h) => h.url)],
    notes: `Username enumeration (${mode}). ${found.length} site(s) reported as present. Treat all hits as POSSIBLE until independently verified.`,
  };

  const evidence: EvidenceRecord[] = found.map((h) => {
    const id = `ev-sherlock-${h.site.toLowerCase().replace(/\s+/g, '-')}-${randomUUID().slice(0, 8)}`;
    return {
      id,
      title: `${h.site} profile for ${username}`,
      url: h.url,
      archiveUrl: `https://web.archive.org/web/*/${encodeURIComponent(h.url)}`,
      confidence,
      entityIds: [entityId],
      notes: `Detected via ${h.source}. Status=${h.status}${h.httpStatus ? ` HTTP ${h.httpStatus}` : ''}. POSSIBLE match only — corroborate before treating as same individual.`,
      tags: ['username-enumeration', 'sherlock', h.site.toLowerCase().replace(/\s+/g, '-'), h.source],
      eventDate: now,
      date: now,
      attachments: [],
    };
  });

  const provenance: ProvenanceStep[] = evidence.map((ev) => ({
    id: `prov-${ev.id}`,
    entityId,
    evidenceId: ev.id,
    claim: `Username "${username}" appears present on ${ev.title.replace(` profile for ${username}`, '')}. Confidence: POSSIBLE / ${confidence}.`,
    notes: `Evidence chain: ${ev.id} ← ${mode}`,
  }));

  return { evidence, entities: found.length ? [entity] : [], provenance };
}

export async function scanUsername(rawUsername: string): Promise<SherlockScanResult> {
  const username = sanitizeUsername(rawUsername);
  if (!username) {
    return {
      username: rawUsername,
      mode: 'node-fallback',
      hits: [],
      evidence: [],
      entities: [],
      provenance: [],
      notes: [
        'Invalid username. Allowed: 1–39 chars of letters, digits, dot, underscore, hyphen.',
      ],
    };
  }

  const notes: string[] = [];
  let mode: SherlockScanResult['mode'] = 'node-fallback';
  let hits: SherlockHit[] = [];

  const hasCli = await isSherlockCliAvailable();
  if (hasCli) {
    try {
      hits = await runSherlockCli(username);
      mode = 'sherlock-cli';
      notes.push('Used Sherlock CLI (full site list).');
    } catch (err) {
      notes.push(
        `Sherlock CLI failed (${err instanceof Error ? err.message : 'unknown'}); fell back to Node checks.`
      );
      hits = await runNodeFallback(username);
      mode = 'node-fallback';
    }
  } else {
    notes.push(
      'Sherlock CLI not found on PATH. Using Node fallback (limited site set). Install with: pipx install sherlock-project'
    );
    hits = await runNodeFallback(username);
    mode = 'node-fallback';
  }

  const { evidence, entities, provenance } = toEvidenceAndEntities(
    username,
    hits,
    mode
  );

  notes.push(
    `${hits.filter((h) => h.status === 'found').length} found, ` +
      `${hits.filter((h) => h.status === 'not_found').length} not found, ` +
      `${hits.filter((h) => h.status === 'error').length} errors.`
  );
  notes.push(
    'All hits are POSSIBLE only. Do not treat username reuse as identity proof without further corroboration.'
  );

  return {
    username,
    mode,
    hits,
    evidence,
    entities,
    provenance,
    notes,
  };
}

export async function scanUsernames(
  usernames: string[]
): Promise<SherlockScanResult[]> {
  const unique = [...new Set(usernames.map((u) => u.trim()).filter(Boolean))];
  const results: SherlockScanResult[] = [];
  for (const u of unique.slice(0, 10)) {
    results.push(await scanUsername(u));
  }
  return results;
}
