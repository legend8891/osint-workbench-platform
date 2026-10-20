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
const BROWSER_USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36 OSINT-Workbench/0.12';
const REQUEST_TIMEOUT_MS = 10_000;
const FALLBACK_CONCURRENCY = 6;

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

type FallbackSite = {
  name: string;
  url: (username: string) => string;
  exists?: (status: number, body: string) => boolean;
};

const USERNAME_RE = /^[\p{L}\p{N}._-]{1,64}$/u;
const NOT_FOUND_MARKERS =
  /(?:page not found|404 not found|user not found|profile not found|doesn't exist|does not exist|nobody on reddit goes by that name|no such user|this account doesn't exist|this page isn't available|couldn't find this account|the page you requested could not be found)/i;

const FALLBACK_SITE_DEFINITIONS: Array<[string, (username: string) => string]> = [
  ['GitHub', (u) => `https://github.com/${encodeURIComponent(u)}`],
  ['GitLab', (u) => `https://gitlab.com/${encodeURIComponent(u)}`],
  ['Reddit', (u) => `https://www.reddit.com/user/${encodeURIComponent(u)}`],
  ['Hacker News', (u) => `https://news.ycombinator.com/user?id=${encodeURIComponent(u)}`],
  ['Keybase', (u) => `https://keybase.io/${encodeURIComponent(u)}`],
  ['Dev.to', (u) => `https://dev.to/${encodeURIComponent(u)}`],
  ['About.me', (u) => `https://about.me/${encodeURIComponent(u)}`],
  ['Linktree', (u) => `https://linktr.ee/${encodeURIComponent(u)}`],
  ['Medium', (u) => `https://medium.com/@${encodeURIComponent(u)}`],
  ['Flickr', (u) => `https://www.flickr.com/people/${encodeURIComponent(u)}`],
  ['Pinterest', (u) => `https://www.pinterest.com/${encodeURIComponent(u)}/`],
  ['Tumblr', (u) => `https://${encodeURIComponent(u)}.tumblr.com/`],
  ['Twitch', (u) => `https://www.twitch.tv/${encodeURIComponent(u)}`],
  ['Steam', (u) => `https://steamcommunity.com/id/${encodeURIComponent(u)}`],
  ['Patreon', (u) => `https://www.patreon.com/${encodeURIComponent(u)}`],
  ['Buy Me a Coffee', (u) => `https://www.buymeacoffee.com/${encodeURIComponent(u)}`],
  ['Ko-fi', (u) => `https://ko-fi.com/${encodeURIComponent(u)}`],
  ['Dribbble', (u) => `https://dribbble.com/${encodeURIComponent(u)}`],
  ['Behance', (u) => `https://www.behance.net/${encodeURIComponent(u)}`],
  ['CodePen', (u) => `https://codepen.io/${encodeURIComponent(u)}`],
  ['npm', (u) => `https://www.npmjs.com/~${encodeURIComponent(u)}`],
  ['PyPI', (u) => `https://pypi.org/user/${encodeURIComponent(u)}/`],
  ['Docker Hub', (u) => `https://hub.docker.com/u/${encodeURIComponent(u)}`],
  ['Hugging Face', (u) => `https://huggingface.co/${encodeURIComponent(u)}`],
  ['Replit', (u) => `https://replit.com/@${encodeURIComponent(u)}`],
  ['Kaggle', (u) => `https://www.kaggle.com/${encodeURIComponent(u)}`],
  ['Product Hunt', (u) => `https://www.producthunt.com/@${encodeURIComponent(u)}`],
  ['Letterboxd', (u) => `https://letterboxd.com/${encodeURIComponent(u)}/`],
  ['Goodreads', (u) => `https://www.goodreads.com/user/show/${encodeURIComponent(u)}`],
  ['Last.fm', (u) => `https://www.last.fm/user/${encodeURIComponent(u)}`],
  ['SoundCloud', (u) => `https://soundcloud.com/${encodeURIComponent(u)}`],
  ['Mixcloud', (u) => `https://www.mixcloud.com/${encodeURIComponent(u)}/`],
  ['Gravatar', (u) => `https://gravatar.com/${encodeURIComponent(u)}`],
  ['X', (u) => `https://x.com/${encodeURIComponent(u)}`],
  ['Instagram', (u) => `https://www.instagram.com/${encodeURIComponent(u)}/`],
  ['TikTok', (u) => `https://www.tiktok.com/@${encodeURIComponent(u)}`],
  ['Telegram', (u) => `https://t.me/${encodeURIComponent(u)}`],
  ['Mastodon', (u) => `https://mastodon.social/@${encodeURIComponent(u)}`],
  ['Bluesky', (u) => `https://bsky.app/profile/${encodeURIComponent(u)}`],
  ['Threads', (u) => `https://www.threads.net/@${encodeURIComponent(u)}`],
];

const FALLBACK_SITES: FallbackSite[] = FALLBACK_SITE_DEFINITIONS.map(([name, url]) => ({
  name: name as string,
  url: url as (username: string) => string,
  exists: (status, body) => status >= 200 && status < 300 && !NOT_FOUND_MARKERS.test(body),
}));

function sanitizeUsername(raw: string): string | null {
  const username = raw.trim().replace(/^@/, '');
  return USERNAME_RE.test(username) ? username : null;
}

async function isSherlockCliAvailable(): Promise<boolean> {
  try {
    await execFileAsync('sherlock', ['--version'], { timeout: 5000 });
    return true;
  } catch {
    try {
      await execFileAsync('python3', ['-m', 'sherlock_project', '--version'], { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }
}

function parseSherlockStdout(stdout: string): SherlockHit[] {
  const hits: SherlockHit[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const found = line.match(/\[\+\]\s+([^:]+):\s+(https?:\/\/\S+)/i);
    if (found) {
      hits.push({ site: found[1].trim(), url: found[2].trim(), status: 'found', source: 'sherlock-cli' });
      continue;
    }
    const notFound = line.match(/\[-\]\s+([^:]+):/i);
    if (notFound) {
      hits.push({ site: notFound[1].trim(), url: '', status: 'not_found', source: 'sherlock-cli' });
    }
  }
  return hits;
}

async function runSherlockCli(username: string): Promise<SherlockHit[]> {
  const args = [username, '--no-color', '--timeout', '10'];
  let stdout = '';
  try {
    const result = await execFileAsync('sherlock', args, {
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    stdout = `${result.stdout}\n${result.stderr || ''}`;
  } catch (firstError: unknown) {
    try {
      const result = await execFileAsync('python3', ['-m', 'sherlock_project', ...args], {
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
      });
      stdout = `${result.stdout}\n${result.stderr || ''}`;
    } catch (secondError: unknown) {
      const error = secondError as { stdout?: string; stderr?: string };
      stdout = `${error.stdout || ''}\n${error.stderr || ''}`;
      if (!stdout.trim()) throw firstError;
    }
  }
  return parseSherlockStdout(stdout);
}

async function scanFallbackSite(site: FallbackSite, username: string): Promise<SherlockHit> {
  const url = site.url(username);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': BROWSER_USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
      },
    });
    const body = await response.text().catch(() => '');
    const status = response.status;
    if (status === 401 || status === 403 || status === 429 || status >= 500) {
      return { site: site.name, url: '', status: 'error', httpStatus: status, source: 'node-fallback' };
    }
    const exists = site.exists?.(status, body) ?? (status >= 200 && status < 300);
    return {
      site: site.name,
      url: exists ? url : '',
      status: exists ? 'found' : 'not_found',
      httpStatus: status,
      source: 'node-fallback',
    };
  } catch {
    return { site: site.name, url: '', status: 'error', source: 'node-fallback' };
  } finally {
    clearTimeout(timer);
  }
}

async function runNodeFallback(username: string): Promise<SherlockHit[]> {
  const hits: SherlockHit[] = [];
  let next = 0;
  async function worker() {
    while (next < FALLBACK_SITES.length) {
      const index = next++;
      hits[index] = await scanFallbackSite(FALLBACK_SITES[index], username);
    }
  }
  await Promise.all(Array.from({ length: Math.min(FALLBACK_CONCURRENCY, FALLBACK_SITES.length) }, worker));
  return hits;
}

function toEvidenceAndEntities(
  username: string,
  hits: SherlockHit[],
  mode: SherlockScanResult['mode']
): Pick<SherlockScanResult, 'evidence' | 'entities' | 'provenance'> {
  const today = new Date().toISOString().slice(0, 10);
  const found = hits.filter((hit) => hit.status === 'found' && hit.url);
  const confidence: Confidence =
    mode === 'sherlock-cli' && found.length >= 3 ? 'Medium' : found.length ? 'Low' : 'Unverified';
  const entityId = `entity-sherlock-${username}-${randomUUID().slice(0, 8)}`;
  const entity: EntityRecord = {
    id: entityId,
    name: username,
    type: 'Username',
    confidence,
    identifiers: [username, ...found.map((hit) => hit.url)],
    notes: `Username enumeration (${mode}). ${found.length} site(s) reported as present. Treat all hits as POSSIBLE until independently verified.`,
  };
  const evidence: EvidenceRecord[] = found.map((hit) => {
    const id = `ev-sherlock-${hit.site.toLowerCase().replace(/\s+/g, '-')}-${randomUUID().slice(0, 8)}`;
    return {
      id,
      title: `${hit.site} profile for ${username}`,
      url: hit.url,
      archiveUrl: `https://web.archive.org/web/*/${encodeURIComponent(hit.url)}`,
      confidence,
      entityIds: [entityId],
      notes: `Detected via ${hit.source}. Status=${hit.status}${hit.httpStatus ? ` HTTP ${hit.httpStatus}` : ''}. POSSIBLE match only — corroborate before treating as same individual.`,
      tags: ['username-enumeration', 'sherlock', hit.site.toLowerCase().replace(/\s+/g, '-'), hit.source],
      eventDate: today,
      date: today,
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
  return { evidence, entities: [entity], provenance };
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
      notes: ['Invalid username. Allowed: 1–64 Unicode letters, digits, dot, underscore, or hyphen; a leading @ is optional.'],
    };
  }

  const notes: string[] = [];
  let mode: SherlockScanResult['mode'] = 'node-fallback';
  let hits: SherlockHit[];
  if (await isSherlockCliAvailable()) {
    try {
      hits = await runSherlockCli(username);
      mode = 'sherlock-cli';
      notes.push('Used Sherlock CLI (full site list).');
    } catch (error) {
      notes.push(`Sherlock CLI failed (${error instanceof Error ? error.message : 'unknown'}); fell back to Node checks.`);
      hits = await runNodeFallback(username);
    }
  } else {
    notes.push(`Sherlock CLI not found on PATH. Using Node fallback (${FALLBACK_SITES.length} sites). Install sherlock-project for the full site list.`);
    hits = await runNodeFallback(username);
  }

  const { evidence, entities, provenance } = toEvidenceAndEntities(username, hits, mode);
  notes.push(`${hits.filter((hit) => hit.status === 'found').length} found, ${hits.filter((hit) => hit.status === 'not_found').length} not found, ${hits.filter((hit) => hit.status === 'error').length} blocked/errors.`);
  notes.push('All hits are POSSIBLE only. Do not treat username reuse as identity proof without further corroboration.');
  return { username, mode, hits, evidence, entities, provenance, notes };
}

export async function scanUsernames(usernames: string[]): Promise<SherlockScanResult[]> {
  const unique = [...new Set(usernames.map((username) => username.trim()).filter(Boolean))];
  const results: SherlockScanResult[] = [];
  for (const username of unique.slice(0, 10)) results.push(await scanUsername(username));
  return results;
}
