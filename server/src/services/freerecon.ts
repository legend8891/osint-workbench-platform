/**
 * Free, no-API-key OSINT providers.
 *
 * These run without any configuration so the workbench is useful out of the box.
 * All sources are public and require no key:
 *
 *   dns      – Cloudflare DNS-over-HTTPS (A / AAAA / MX / TXT / NS / CNAME)
 *   rdap     – RDAP domain registration (rdap.org)
 *   crtsh    – Certificate Transparency subdomains (crt.sh)
 *   ipgeo    – IP geolocation + ASN (ipwho.is)
 *   gravatar – Gravatar profile for an email (gravatar.com)
 *   wayback  – Wayback Machine archived snapshots (archive.org)
 *
 * Findings are POSSIBLE / Low confidence until an analyst verifies them.
 * Nothing here is invented: every hit maps to a real upstream response.
 */

import { createHash, randomUUID } from 'node:crypto';
import { withProviderThrottle } from './throttle.js';
import type {
  Confidence,
  ProviderEntity,
  ProviderEvidence,
  ProviderHit,
  ProviderLookupResult,
  ProviderProvenance,
} from './providers.js';

function id(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function makeEntity(
  name: string,
  type: string,
  identifiers: string[],
  notes: string,
  confidence: Confidence = 'Low'
): ProviderEntity {
  return {
    id: id('ent'),
    name,
    type,
    identifiers: [...new Set(identifiers.filter(Boolean))],
    confidence,
    notes,
  };
}

function makeEvidence(
  title: string,
  url: string,
  tags: string[],
  entityId: string,
  notes = ''
): ProviderEvidence {
  const d = today();
  return {
    id: id('ev'),
    title,
    url,
    archiveUrl: url ? `https://web.archive.org/web/*/${url}` : '',
    tags,
    confidence: 'Low',
    entityIds: entityId ? [entityId] : [],
    notes,
    eventDate: d,
    date: d,
    attachments: [],
  };
}

function makeProv(
  entityId: string,
  evidenceId: string,
  claim: string,
  notes = ''
): ProviderProvenance {
  return { id: id('prov'), entityId, evidenceId, claim, notes };
}

function emptyResult(
  provider: string,
  query: string,
  queryType: string,
  error: string
): ProviderLookupResult {
  return {
    provider,
    query,
    queryType,
    configured: true,
    ok: false,
    error,
    hits: [],
    rawSummary: error,
    entities: [],
    evidence: [],
    provenance: [],
  };
}

type JsonResult = {
  ok: boolean;
  status: number;
  data: unknown;
  error?: string;
};

/** GET JSON with a hard timeout. Never throws — returns an error field instead. */
async function getJson(
  url: string,
  opts: { headers?: Record<string, string>; timeoutMs?: number } = {}
): Promise<JsonResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await fetch(url, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'osint-workbench-platform (research; respectful)',
        ...(opts.headers || {}),
      },
      signal: controller.signal,
    });
    const text = await res.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text.slice(0, 500) };
    }
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      data: null,
      error: err instanceof Error ? err.message : 'request failed',
    };
  } finally {
    clearTimeout(timer);
  }
}

function throttled<T>(fn: () => Promise<T>): Promise<T> {
  return withProviderThrottle('default', fn);
}

export function inferTargetType(
  target: string
): 'email' | 'ip' | 'domain' | 'url' | 'username' {
  const t = target.trim();
  if (/^https?:\/\//i.test(t)) return 'url';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return 'email';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return 'ip';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t) && !t.includes(' ')) return 'domain';
  return 'username';
}

/* ------------------------------------------------------------------ DNS */

const DNS_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'] as const;

export async function lookupDns(domain: string): Promise<ProviderLookupResult> {
  const provider = 'dns';
  const queryType = 'domain';
  const hits: ProviderHit[] = [];
  const identifiers: string[] = [domain];
  const perType: Record<string, string[]> = {};

  await Promise.all(
    DNS_TYPES.map(async (type) => {
      const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
        domain
      )}&type=${type}`;
      const { ok, data } = await throttled(() =>
        getJson(url, { headers: { Accept: 'application/dns-json' }, timeoutMs: 12_000 })
      );
      if (!ok || !data || typeof data !== 'object') return;
      const answers = Array.isArray((data as { Answer?: unknown[] }).Answer)
        ? ((data as { Answer: Array<{ data?: unknown; TTL?: unknown }> }).Answer)
        : [];
      const values = answers
        .map((a) => String(a.data ?? '').trim())
        .filter(Boolean);
      if (values.length === 0) return;
      perType[type] = values;
      for (const v of values) {
        identifiers.push(v);
        hits.push({
          title: `${type}: ${v}`,
          url: '',
          detail: `TTL ${answers[0]?.TTL ?? ''}`.trim(),
          tags: ['dns', type.toLowerCase()],
        });
      }
    })
  );

  if (hits.length === 0) {
    const entity = makeEntity(domain, 'domain', [domain], 'DNS: no records returned');
    return {
      provider,
      query: domain,
      queryType,
      configured: true,
      ok: true,
      hits: [],
      rawSummary: 'No DNS records returned (domain may not resolve).',
      entities: [entity],
      evidence: [],
      provenance: [
        makeProv(entity.id, '', `DNS lookup for ${domain} returned no records`, 'Cloudflare DoH'),
      ],
    };
  }

  const summary = Object.entries(perType)
    .map(([t, v]) => `${t}=${v.length}`)
    .join(' ');
  const entity = makeEntity(
    domain,
    'domain',
    identifiers,
    `DNS records: ${summary}`
  );
  const evidence = [
    makeEvidence(
      `DNS records for ${domain}`,
      `https://dns.google/query?name=${encodeURIComponent(domain)}`,
      ['dns', 'domain'],
      entity.id,
      summary
    ),
  ];
  return {
    provider,
    query: domain,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `DNS: ${summary}`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `Resolved ${hits.length} DNS record(s) for ${domain}`, 'Cloudflare DoH'),
    ],
  };
}

/* ----------------------------------------------------------------- RDAP */

type RdapEvent = { eventAction?: string; eventDate?: string };
type RdapEntity = {
  roles?: string[];
  vcardArray?: unknown[];
};
type RdapNameServer = { ldhName?: string };

export async function lookupRdap(domain: string): Promise<ProviderLookupResult> {
  const provider = 'rdap';
  const queryType = 'domain';
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 15_000 }));

  if (status === 404) {
    return emptyResult(provider, domain, queryType, 'No RDAP record for this domain');
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, domain, queryType, `RDAP lookup failed (HTTP ${status})`);
  }

  const d = data as {
    events?: RdapEvent[];
    status?: string[];
    nameservers?: RdapNameServer[];
    entities?: RdapEntity[];
    handle?: string;
  };
  const events = Array.isArray(d.events) ? d.events : [];
  const pick = (action: string) =>
    events.find((e) => e.eventAction === action)?.eventDate ?? '';
  const registration = pick('registration');
  const expiration = pick('expiration');
  const lastChanged = pick('last changed');
  const statuses = Array.isArray(d.status) ? d.status : [];
  const nameservers = Array.isArray(d.nameservers)
    ? d.nameservers.map((n) => String(n.ldhName ?? '').toLowerCase()).filter(Boolean)
    : [];

  let registrar = '';
  const entities = Array.isArray(d.entities) ? d.entities : [];
  const registrarEntity = entities.find((e) => (e.roles ?? []).includes('registrar'));
  if (registrarEntity && Array.isArray(registrarEntity.vcardArray)) {
    const vcard = registrarEntity.vcardArray[1];
    if (Array.isArray(vcard)) {
      const fn = vcard.find((row) => Array.isArray(row) && row[0] === 'fn');
      if (Array.isArray(fn) && fn[3]) registrar = String(fn[3]);
    }
  }

  const identifiers = [domain, registrar, ...nameservers].filter(Boolean);
  const entity = makeEntity(
    domain,
    'domain',
    identifiers,
    `RDAP: registered ${registration || 'n/a'}; expires ${expiration || 'n/a'}; registrar ${registrar || 'n/a'}`
  );
  const hits: ProviderHit[] = [
    ...(registration ? [{ title: `registered: ${registration}`, url: '', detail: '', tags: ['rdap'] }] : []),
    ...(expiration ? [{ title: `expires: ${expiration}`, url: '', detail: '', tags: ['rdap'] }] : []),
    ...(lastChanged ? [{ title: `last changed: ${lastChanged}`, url: '', detail: '', tags: ['rdap'] }] : []),
    ...(registrar ? [{ title: `registrar: ${registrar}`, url: '', detail: '', tags: ['rdap'] }] : []),
    ...nameservers.map((n) => ({ title: `ns: ${n}`, url: '', detail: '', tags: ['rdap', 'nameserver'] })),
    ...statuses.map((s) => ({ title: `status: ${s}`, url: '', detail: '', tags: ['rdap', 'status'] })),
  ];
  const evidence = [
    makeEvidence(
      `RDAP registration for ${domain}`,
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      ['rdap', 'whois', 'domain'],
      entity.id,
      entity.notes
    ),
  ];
  return {
    provider,
    query: domain,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `RDAP: registered=${registration || 'n/a'} expires=${expiration || 'n/a'} registrar=${registrar || 'n/a'}`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `RDAP registration record for ${domain}`, 'rdap.org'),
    ],
  };
}

/* ---------------------------------------------------------------- crt.sh */

export async function lookupCrtSh(domain: string): Promise<ProviderLookupResult> {
  const provider = 'crtsh';
  const queryType = 'domain';
  const url = `https://crt.sh/?q=${encodeURIComponent('%25.' + domain)}&output=json`;

  // crt.sh is frequently overloaded and returns 502/HTML. Retry a few times.
  let rows: Array<{ name_value?: string }> | null = null;
  let lastStatus = 0;
  for (let attempt = 0; attempt < 3 && !rows; attempt += 1) {
    const { ok, status, data } = await throttled(() =>
      getJson(url, { timeoutMs: 20_000 })
    );
    lastStatus = status;
    if (ok && Array.isArray(data)) {
      rows = data as Array<{ name_value?: string }>;
      break;
    }
    if (attempt < 2) await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }

  if (!rows) {
    return emptyResult(
      provider,
      domain,
      queryType,
      `crt.sh unavailable right now (last HTTP ${lastStatus || 'error'}). It is often overloaded — try again shortly.`
    );
  }

  const names = new Set<string>();
  for (const row of rows) {
    for (const nv of String(row.name_value ?? '').split('\n')) {
      const n = nv.trim().toLowerCase();
      if (n && !n.startsWith('*')) names.add(n);
    }
  }
  const subdomains = [...names].filter((n) => n !== domain).sort();
  const all = [domain, ...subdomains];

  const entity = makeEntity(
    domain,
    'domain',
    all.slice(0, 60),
    `Certificate Transparency: ${subdomains.length} subdomain(s) observed`
  );
  const hits: ProviderHit[] = all.slice(0, 60).map((n) => ({
    title: n,
    url: `https://${n}`,
    detail: n === domain ? 'apex' : 'subdomain',
    tags: ['crtsh', 'subdomain'],
  }));
  const evidence = [
    makeEvidence(
      `Certificate Transparency for ${domain}`,
      `https://crt.sh/?q=${encodeURIComponent('%25.' + domain)}`,
      ['crtsh', 'subdomain', 'certificate'],
      entity.id,
      `${subdomains.length} subdomain(s) from CT logs`
    ),
  ];
  return {
    provider,
    query: domain,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `crt.sh: ${subdomains.length} subdomain(s)`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `crt.sh observed ${subdomains.length} subdomain(s) for ${domain}`, 'crt.sh'),
    ],
  };
}

/* ------------------------------------------------------------ HackerTarget */

/** Subdomain discovery via HackerTarget hostsearch (free, no key, 100/day/IP). */
export async function lookupHostSearch(domain: string): Promise<ProviderLookupResult> {
  const provider = 'hostsearch';
  const queryType = 'domain';
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 20_000 }));

  const raw =
    data && typeof data === 'object' && 'raw' in data
      ? String((data as { raw?: string }).raw ?? '')
      : '';
  if (!ok || !raw.trim() || /error|API count exceeded|no records/i.test(raw)) {
    return emptyResult(
      provider,
      domain,
      queryType,
      raw.trim() && /error|exceeded|no records/i.test(raw)
        ? raw.trim().slice(0, 200)
        : `HackerTarget hostsearch failed (HTTP ${status})`
    );
  }

  const rows = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [host, ip] = l.split(',');
      return { host: (host ?? '').toLowerCase(), ip: (ip ?? '').trim() };
    })
    .filter((r) => r.host && r.host.endsWith(domain.toLowerCase()));

  const hosts = [...new Set(rows.map((r) => r.host))].sort();
  const ips = [...new Set(rows.map((r) => r.ip).filter(Boolean))];

  const entity = makeEntity(
    domain,
    'domain',
    [domain, ...hosts.slice(0, 60), ...ips.slice(0, 20)],
    `HackerTarget: ${hosts.length} host(s), ${ips.length} IP(s)`
  );
  const hits: ProviderHit[] = rows.slice(0, 80).map((r) => ({
    title: r.host,
    url: `https://${r.host}`,
    detail: r.ip,
    tags: ['hostsearch', 'subdomain'],
  }));
  const evidence = [
    makeEvidence(
      `HackerTarget hostsearch for ${domain}`,
      `https://hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      ['hostsearch', 'subdomain', 'dns'],
      entity.id,
      `${hosts.length} host(s) resolved`
    ),
  ];
  return {
    provider,
    query: domain,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `HackerTarget: ${hosts.length} host(s), ${ips.length} IP(s)`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `HackerTarget hostsearch found ${hosts.length} host(s) for ${domain}`, 'api.hackertarget.com'),
    ],
  };
}

/* --------------------------------------------------------------- ipwho.is */

export async function lookupIpGeo(ip: string): Promise<ProviderLookupResult> {
  const provider = 'ipgeo';
  const queryType = 'ip';
  const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 12_000 }));

  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, ip, queryType, `IP geolocation failed (HTTP ${status})`);
  }
  const d = data as {
    success?: boolean;
    message?: string;
    country?: string;
    country_code?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: { id?: string };
    connection?: { isp?: string; org?: string; asn?: number; domain?: string };
  };
  if (d.success === false) {
    return emptyResult(provider, ip, queryType, String(d.message ?? 'ipwho.is error'));
  }

  const isp = d.connection?.isp ?? '';
  const org = d.connection?.org ?? '';
  const asn = d.connection?.asn != null ? `AS${d.connection.asn}` : '';
  const place = [d.city, d.region, d.country].filter(Boolean).join(', ');
  const coords =
    d.latitude != null && d.longitude != null ? `${d.latitude}, ${d.longitude}` : '';

  const entity = makeEntity(
    ip,
    'ip',
    [ip, isp, org, asn, d.country_code ?? ''].filter(Boolean),
    `Geo: ${place || 'n/a'}; ISP ${isp || 'n/a'}; ${asn || 'n/a'}`
  );
  const hits: ProviderHit[] = [
    ...(place ? [{ title: `location: ${place}`, url: '', detail: '', tags: ['ipgeo'] }] : []),
    ...(coords ? [{ title: `coords: ${coords}`, url: `https://www.openstreetmap.org/?mlat=${d.latitude}&mlon=${d.longitude}#map=12/${d.latitude}/${d.longitude}`, detail: '', tags: ['ipgeo', 'map'] }] : []),
    ...(isp ? [{ title: `isp: ${isp}`, url: '', detail: org, tags: ['ipgeo'] }] : []),
    ...(asn ? [{ title: asn, url: '', detail: d.connection?.domain ?? '', tags: ['ipgeo', 'asn'] }] : []),
    ...(d.timezone?.id ? [{ title: `timezone: ${d.timezone.id}`, url: '', detail: '', tags: ['ipgeo'] }] : []),
  ];
  const evidence = [
    makeEvidence(
      `IP geolocation for ${ip}`,
      `https://ipwho.is/${encodeURIComponent(ip)}`,
      ['ipgeo', 'ip', 'geolocation'],
      entity.id,
      entity.notes
    ),
  ];
  return {
    provider,
    query: ip,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `Geo: ${place || 'n/a'} · ISP ${isp || 'n/a'} · ${asn || 'n/a'}`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `ipwho.is geolocated ${ip} to ${place || 'unknown'}`, 'ipwho.is'),
    ],
  };
}

/* ------------------------------------------------------- Shodan InternetDB */

/**
 * Shodan InternetDB (https://internetdb.shodan.io) — free, no API key.
 * Returns open ports, hostnames, CPEs, known CVEs and tags for an IP.
 * A 404 means the IP simply has no recorded exposure data.
 */
export async function lookupInternetDb(ip: string): Promise<ProviderLookupResult> {
  const provider = 'internetdb';
  const queryType = 'ip';
  const url = `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 12_000 }));

  if (status === 404) {
    const entity = makeEntity(ip, 'ip', [ip], 'InternetDB: no exposure data');
    return {
      provider,
      query: ip,
      queryType,
      configured: true,
      ok: true,
      hits: [],
      rawSummary: 'InternetDB has no data for this IP.',
      entities: [entity],
      evidence: [],
      provenance: [
        makeProv(entity.id, '', `InternetDB has no data for ${ip}`, 'internetdb.shodan.io'),
      ],
    };
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, ip, queryType, `InternetDB lookup failed (HTTP ${status})`);
  }

  const d = data as {
    hostnames?: string[];
    ports?: number[];
    cpes?: string[];
    tags?: string[];
    vulns?: string[];
  };
  const hostnames = Array.isArray(d.hostnames) ? d.hostnames : [];
  const ports = Array.isArray(d.ports) ? d.ports : [];
  const cpes = Array.isArray(d.cpes) ? d.cpes : [];
  const tags = Array.isArray(d.tags) ? d.tags : [];
  const vulns = Array.isArray(d.vulns) ? d.vulns : [];

  const entity = makeEntity(
    ip,
    'ip',
    [ip, ...hostnames],
    `InternetDB: ${ports.length} open port(s), ${vulns.length} CVE(s)${tags.length ? `, tags: ${tags.join(', ')}` : ''}`
  );
  const hits: ProviderHit[] = [
    ...ports.map((p) => ({ title: `port ${p}`, url: '', detail: '', tags: ['internetdb', 'port'] })),
    ...hostnames.map((h) => ({ title: `hostname: ${h}`, url: `https://${h}`, detail: '', tags: ['internetdb', 'hostname'] })),
    ...cpes.map((c) => ({ title: `cpe: ${c}`, url: '', detail: '', tags: ['internetdb', 'cpe'] })),
    ...vulns.map((v) => ({ title: `CVE: ${v}`, url: `https://nvd.nist.gov/vuln/detail/${v}`, detail: '', tags: ['internetdb', 'cve'] })),
    ...tags.map((t) => ({ title: `tag: ${t}`, url: '', detail: '', tags: ['internetdb', 'tag'] })),
  ];
  const evidence = [
    makeEvidence(
      `Shodan InternetDB exposure for ${ip}`,
      `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
      ['internetdb', 'ip', 'exposure'],
      entity.id,
      entity.notes
    ),
  ];
  return {
    provider,
    query: ip,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `InternetDB: ${ports.length} port(s)${vulns.length ? `, ${vulns.length} CVE(s)` : ''}${tags.length ? `, tags: ${tags.join(', ')}` : ''}`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `InternetDB reported ${ports.length} open port(s) for ${ip}`, 'internetdb.shodan.io'),
    ],
  };
}

/* --------------------------------------------------------------- IP RDAP */

/**
 * IP RDAP (rdap.org → the responsible RIR) — free, no API key.
 * Returns the registered network block, allocation country and organisation.
 */
export async function lookupIpRdap(ip: string): Promise<ProviderLookupResult> {
  const provider = 'iprdap';
  const queryType = 'ip';
  const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 15_000 }));

  if (status === 404) {
    return emptyResult(provider, ip, queryType, 'No RDAP record for this IP');
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, ip, queryType, `IP RDAP lookup failed (HTTP ${status})`);
  }

  const d = data as {
    handle?: string;
    name?: string;
    type?: string;
    country?: string;
    startAddress?: string;
    endAddress?: string;
    events?: RdapEvent[];
    entities?: RdapEntity[];
  };
  const events = Array.isArray(d.events) ? d.events : [];
  const pick = (action: string) =>
    events.find((e) => e.eventAction === action)?.eventDate ?? '';
  const range = [d.startAddress, d.endAddress].filter(Boolean).join(' \u2013 ');
  const netname = d.name ?? d.handle ?? '';

  let org = '';
  const entities = Array.isArray(d.entities) ? d.entities : [];
  for (const ent of entities) {
    if (!Array.isArray(ent.vcardArray)) continue;
    const vcard = ent.vcardArray[1];
    if (!Array.isArray(vcard)) continue;
    const fn = vcard.find((row) => Array.isArray(row) && row[0] === 'fn');
    if (Array.isArray(fn) && fn[3]) {
      org = String(fn[3]);
      break;
    }
  }

  const identifiers = [ip, netname, range, d.country ?? '', org].filter(Boolean);
  const entity = makeEntity(
    netname || ip,
    'ip',
    identifiers,
    `IP RDAP: ${range || 'n/a'}${d.country ? `, ${d.country}` : ''}${org ? `, ${org}` : ''}`
  );
  const hits: ProviderHit[] = [
    ...(netname ? [{ title: `network: ${netname}`, url: '', detail: '', tags: ['iprdap'] }] : []),
    ...(range ? [{ title: `range: ${range}`, url: '', detail: '', tags: ['iprdap'] }] : []),
    ...(d.country ? [{ title: `country: ${d.country}`, url: '', detail: '', tags: ['iprdap'] }] : []),
    ...(org ? [{ title: `org: ${org}`, url: '', detail: '', tags: ['iprdap'] }] : []),
    ...(d.type ? [{ title: `type: ${d.type}`, url: '', detail: '', tags: ['iprdap'] }] : []),
    ...(pick('registration')
      ? [{ title: `registered: ${pick('registration')}`, url: '', detail: '', tags: ['iprdap'] }]
      : []),
    ...(pick('last changed')
      ? [{ title: `last changed: ${pick('last changed')}`, url: '', detail: '', tags: ['iprdap'] }]
      : []),
  ];
  const evidence = [
    makeEvidence(
      `IP RDAP registration for ${ip}`,
      `https://rdap.org/ip/${encodeURIComponent(ip)}`,
      ['iprdap', 'ip', 'whois'],
      entity.id,
      entity.notes
    ),
  ];
  return {
    provider,
    query: ip,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `IP RDAP: ${range || 'n/a'}${d.country ? ` \u00b7 ${d.country}` : ''}${org ? ` \u00b7 ${org}` : ''}`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `RDAP registered network ${netname || range || ip}`, 'rdap.org'),
    ],
  };
}

/* -------------------------------------------------------------- Gravatar */

export async function lookupGravatar(email: string): Promise<ProviderLookupResult> {
  const provider = 'gravatar';
  const queryType = 'email';
  const hash = createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  const url = `https://gravatar.com/${hash}.json`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 12_000 }));

  if (status === 404) {
    const entity = makeEntity(email, 'email', [email], 'Gravatar: no profile');
    return {
      provider,
      query: email,
      queryType,
      configured: true,
      ok: true,
      hits: [],
      rawSummary: 'No Gravatar profile for this email.',
      entities: [entity],
      evidence: [],
      provenance: [
        makeProv(entity.id, '', `No Gravatar profile found for ${email}`, 'gravatar.com'),
      ],
    };
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, email, queryType, `Gravatar lookup failed (HTTP ${status})`);
  }

  const entry = (data as { entry?: Array<Record<string, unknown>> }).entry?.[0] ?? {};
  const displayName = entry.displayName ? String(entry.displayName) : '';
  const profileUrl = entry.profileUrl ? String(entry.profileUrl) : '';
  const aboutMe = entry.aboutMe ? String(entry.aboutMe) : '';
  const name = entry.name && typeof entry.name === 'object'
    ? Object.values(entry.name as Record<string, unknown>).filter(Boolean).join(' ')
    : '';
  const accounts = Array.isArray(entry.accounts)
    ? (entry.accounts as Array<{ shortname?: string; username?: string; url?: string }>)
    : [];
  const urls = Array.isArray(entry.urls)
    ? (entry.urls as Array<{ title?: string; value?: string }>)
    : [];

  const identifiers = [
    email,
    displayName,
    name,
    profileUrl,
    ...accounts.map((a) => a.username ?? '').filter(Boolean),
  ].filter(Boolean);

  const entity = makeEntity(
    displayName || name || email,
    'person',
    identifiers,
    `Gravatar profile: ${accounts.length} linked account(s)`
  );
  const hits: ProviderHit[] = [
    ...(profileUrl ? [{ title: `profile: ${profileUrl}`, url: profileUrl, detail: '', tags: ['gravatar'] }] : []),
    ...(aboutMe ? [{ title: `about: ${aboutMe.slice(0, 120)}`, url: '', detail: '', tags: ['gravatar'] }] : []),
    ...accounts.map((a) => ({
      title: `${a.shortname ?? 'account'}: ${a.username ?? ''}`.trim(),
      url: a.url ?? '',
      detail: '',
      tags: ['gravatar', 'account'],
    })),
    ...urls.map((u) => ({ title: `${u.title ?? 'url'}: ${u.value ?? ''}`.trim(), url: u.value ?? '', detail: '', tags: ['gravatar'] })),
  ];
  const evidence = [
    makeEvidence(
      `Gravatar profile for ${email}`,
      profileUrl || `https://gravatar.com/${hash}`,
      ['gravatar', 'email', 'profile'],
      entity.id,
      entity.notes
    ),
  ];
  return {
    provider,
    query: email,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `Gravatar: ${displayName || name || 'profile found'} · ${accounts.length} linked account(s)`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `Gravatar profile resolved for ${email}`, 'gravatar.com'),
    ],
  };
}

/* -------------------------------------------------------------- Wayback */

export async function lookupWayback(target: string): Promise<ProviderLookupResult> {
  const provider = 'wayback';
  const queryType = 'url';
  const url = `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`;
  const { ok, status, data } = await throttled(() => getJson(url, { timeoutMs: 12_000 }));

  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, target, queryType, `Wayback lookup failed (HTTP ${status})`);
  }
  const snap = (data as {
    archived_snapshots?: { closest?: { available?: boolean; url?: string; timestamp?: string; status?: string } };
  }).archived_snapshots?.closest;

  if (!snap?.available || !snap.url) {
    const entity = makeEntity(target, 'url', [target], 'Wayback: no snapshots');
    return {
      provider,
      query: target,
      queryType,
      configured: true,
      ok: true,
      hits: [],
      rawSummary: 'No archived snapshots found.',
      entities: [entity],
      evidence: [],
      provenance: [
        makeProv(entity.id, '', `No Wayback snapshots for ${target}`, 'archive.org'),
      ],
    };
  }

  const ts = snap.timestamp ?? '';
  const pretty = ts.length >= 8 ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : ts;
  const entity = makeEntity(target, 'url', [target, snap.url], `Wayback snapshot: ${pretty}`);
  const evidence = [
    makeEvidence(
      `Wayback snapshot of ${target}`,
      snap.url,
      ['wayback', 'archive', 'url'],
      entity.id,
      `Captured ${pretty} (HTTP ${snap.status ?? 'n/a'})`
    ),
  ];
  return {
    provider,
    query: target,
    queryType,
    configured: true,
    ok: true,
    hits: [
      { title: `snapshot: ${pretty}`, url: snap.url, detail: `HTTP ${snap.status ?? ''}`.trim(), tags: ['wayback'] },
    ],
    rawSummary: `Wayback snapshot available (${pretty}).`,
    entities: [entity],
    evidence,
    provenance: [
      makeProv(entity.id, evidence[0].id, `Wayback archived ${target} on ${pretty}`, 'archive.org'),
    ],
  };
}

/* --------------------------------------------------- combined auto-detect */

export type FreeReconResponse = {
  query: string;
  queryType: string;
  scannedAt: string;
  results: ProviderLookupResult[];
};

/**
 * Auto-detect the target type and run every applicable free provider.
 * No API keys required.
 */
export async function runFreeRecon(target: string): Promise<FreeReconResponse> {
  const query = target.trim();
  const queryType = inferTargetType(query);
  const tasks: Promise<ProviderLookupResult>[] = [];

  if (queryType === 'domain') {
    tasks.push(
      lookupDns(query),
      lookupRdap(query),
      lookupHostSearch(query),
      lookupCrtSh(query),
      lookupWayback(query)
    );
  } else if (queryType === 'ip') {
    tasks.push(lookupIpGeo(query), lookupInternetDb(query), lookupIpRdap(query));
  } else if (queryType === 'email') {
    tasks.push(lookupGravatar(query));
  } else if (queryType === 'url') {
    tasks.push(lookupWayback(query));
  }

  const results = tasks.length ? await Promise.all(tasks) : [];
  return {
    query,
    queryType,
    scannedAt: new Date().toISOString(),
    results,
  };
}

export const FREE_PROVIDER_IDS = [
  'dns',
  'rdap',
  'crtsh',
  'hostsearch',
  'ipgeo',
  'internetdb',
  'iprdap',
  'gravatar',
  'wayback',
] as const;
