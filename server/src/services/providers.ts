/**
 * Live OSINT provider calls. Returns only data from the upstream API.
 * No synthetic/sample profiles. All findings are labelled POSSIBLE until analyst verifies.
 */

import { randomUUID } from 'node:crypto';

export type Confidence = 'CONFIRMED' | 'PROBABLE' | 'POSSIBLE' | 'UNKNOWN';

export interface ProviderEntity {
  id: string;
  name: string;
  type: string;
  identifiers: string[];
  confidence: Confidence;
  notes?: string;
}

export interface ProviderEvidence {
  id: string;
  title: string;
  url: string;
  archiveUrl?: string;
  tags: string[];
  confidence: Confidence;
  attachments: string[];
}

export interface ProviderProvenance {
  id: string;
  claim: string;
  source: string;
  method: string;
  confidence: Confidence;
}

export interface ProviderLookupResult {
  provider: string;
  query: string;
  ok: boolean;
  error?: string;
  hits: string[];
  rawSummary?: string;
  entities: ProviderEntity[];
  evidence: ProviderEvidence[];
  provenance: ProviderProvenance[];
}

function id(prefix: string) {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function env(key: string): string | undefined {
  const v = process.env[key]?.trim();
  return v || undefined;
}

async function fetchJson(url: string, init?: RequestInit): Promise<{ ok: boolean; status: number; data: unknown }> {
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.headers || {}),
    },
  });
  let data: unknown = null;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text.slice(0, 500) };
  }
  return { ok: res.ok, status: res.status, data };
}

/** Have I Been Pwned — breach titles for an email (no passwords returned). */
export async function lookupHibp(email: string): Promise<ProviderLookupResult> {
  const key = env('HIBP_API_KEY');
  const provider = 'hibp';
  if (!key) {
    return {
      provider,
      query: email,
      ok: false,
      error: 'HIBP_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const { ok, status, data } = await fetchJson(url, {
    headers: {
      'hibp-api-key': key,
      'user-agent': 'osint-workbench-platform',
    },
  });
  if (status === 404) {
    return {
      provider,
      query: email,
      ok: true,
      hits: [],
      rawSummary: 'No breaches reported for this email.',
      entities: [
        {
          id: id('ent'),
          name: email,
          type: 'email',
          identifiers: [email],
          confidence: 'POSSIBLE',
          notes: 'HIBP: zero breaches',
        },
      ],
      evidence: [],
      provenance: [
        {
          id: id('prov'),
          claim: `HIBP reports no breaches for ${email}`,
          source: 'Have I Been Pwned API',
          method: 'API v3 breachedaccount',
          confidence: 'POSSIBLE',
        },
      ],
    };
  }
  if (!ok || !Array.isArray(data)) {
    return {
      provider,
      query: email,
      ok: false,
      error: `HIBP HTTP ${status}`,
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const breaches = data as Array<Record<string, unknown>>;
  const titles = breaches.map((b) => String(b.Name || b.Title || 'unknown')).filter(Boolean);
  const entityId = id('ent');
  return {
    provider,
    query: email,
    ok: true,
    hits: titles,
    rawSummary: `${titles.length} breach(es): ${titles.slice(0, 12).join(', ')}${titles.length > 12 ? '…' : ''}`,
    entities: [
      {
        id: entityId,
        name: email,
        type: 'email',
        identifiers: [email, ...titles.map((t) => `breach:${t}`)],
        confidence: 'POSSIBLE',
        notes: `Appears in ${titles.length} HIBP breach(es)`,
      },
    ],
    evidence: titles.map((t) => ({
      id: id('ev'),
      title: `HIBP breach: ${t}`,
      url: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(t)}`,
      tags: ['hibp', 'breach'],
      confidence: 'POSSIBLE' as Confidence,
      attachments: [],
    })),
    provenance: [
      {
        id: id('prov'),
        claim: `Email ${email} listed in ${titles.length} HIBP breach(es)`,
        source: 'Have I Been Pwned API',
        method: 'API v3 breachedaccount',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** Hunter.io email finder / verifier. */
export async function lookupHunterEmail(email: string): Promise<ProviderLookupResult> {
  const key = env('HUNTER_API_KEY');
  const provider = 'hunter-email';
  if (!key) {
    return {
      provider,
      query: email,
      ok: false,
      error: 'HUNTER_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${encodeURIComponent(key)}`;
  const { ok, data } = await fetchJson(url);
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: email,
      ok: false,
      error: 'Hunter email verifier failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const result = String(d.result || '');
  const score = d.score;
  const sources = Array.isArray(d.sources) ? (d.sources as Array<Record<string, unknown>>) : [];
  const hits = [
    result ? `result:${result}` : '',
    score != null ? `score:${score}` : '',
    ...sources.slice(0, 5).map((s) => String(s.domain || s.uri || '')).filter(Boolean),
  ].filter(Boolean);
  const entityId = id('ent');
  return {
    provider,
    query: email,
    ok: true,
    hits,
    rawSummary: `Hunter result=${result} score=${score ?? 'n/a'} sources=${sources.length}`,
    entities: [
      {
        id: entityId,
        name: email,
        type: 'email',
        identifiers: [email, ...(d.domain ? [String(d.domain)] : [])],
        confidence: 'POSSIBLE',
        notes: `Hunter verifier: ${result} (score ${score ?? 'n/a'})`,
      },
    ],
    evidence: [
      {
        id: id('ev'),
        title: `Hunter email verification: ${result}`,
        url: 'https://hunter.io',
        tags: ['hunter', 'email'],
        confidence: 'POSSIBLE',
        attachments: [],
      },
    ],
    provenance: [
      {
        id: id('prov'),
        claim: `Hunter reports ${email} as ${result}`,
        source: 'Hunter.io API',
        method: 'email-verifier',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** Hunter.io domain search — finds emails for a domain. */
export async function lookupHunterDomain(domain: string): Promise<ProviderLookupResult> {
  const key = env('HUNTER_API_KEY');
  const provider = 'hunter-domain';
  if (!key) {
    return {
      provider,
      query: domain,
      ok: false,
      error: 'HUNTER_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${encodeURIComponent(key)}&limit=10`;
  const { ok, data } = await fetchJson(url);
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: domain,
      ok: false,
      error: 'Hunter domain search failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const emails = Array.isArray(d.emails) ? (d.emails as Array<Record<string, unknown>>) : [];
  const org = d.organization ? String(d.organization) : domain;
  const hits = emails.map((e) => String(e.value || '')).filter(Boolean);
  const entities: ProviderEntity[] = [
    {
      id: id('ent'),
      name: org,
      type: 'organization',
      identifiers: [domain, ...(d.domain ? [String(d.domain)] : [])],
      confidence: 'POSSIBLE',
      notes: `Hunter domain search: ${hits.length} email(s)`,
    },
    ...hits.slice(0, 10).map((em) => ({
      id: id('ent'),
      name: em,
      type: 'email',
      identifiers: [em, domain],
      confidence: 'POSSIBLE' as Confidence,
      notes: `Discovered via Hunter domain-search on ${domain}`,
    })),
  ];
  return {
    provider,
    query: domain,
    ok: true,
    hits,
    rawSummary: `${hits.length} email(s) for ${domain}`,
    entities,
    evidence: hits.slice(0, 10).map((em) => ({
      id: id('ev'),
      title: `Hunter domain email: ${em}`,
      url: `https://hunter.io/search/${encodeURIComponent(domain)}`,
      tags: ['hunter', 'domain', 'email'],
      confidence: 'POSSIBLE' as Confidence,
      attachments: [],
    })),
    provenance: [
      {
        id: id('prov'),
        claim: `Hunter domain-search returned ${hits.length} email(s) for ${domain}`,
        source: 'Hunter.io API',
        method: 'domain-search',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** Numverify phone validation. */
export async function lookupNumverify(phone: string): Promise<ProviderLookupResult> {
  const key = env('NUMVERIFY_API_KEY');
  const provider = 'numverify';
  if (!key) {
    return {
      provider,
      query: phone,
      ok: false,
      error: 'NUMVERIFY_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `http://apilayer.net/api/validate?access_key=${encodeURIComponent(key)}&number=${encodeURIComponent(phone)}`;
  const { ok, data } = await fetchJson(url);
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: phone,
      ok: false,
      error: 'Numverify failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const d = data as Record<string, unknown>;
  const valid = Boolean(d.valid);
  const hits = [
    valid ? 'valid' : 'invalid',
    d.country_name ? `country:${d.country_name}` : '',
    d.carrier ? `carrier:${d.carrier}` : '',
    d.line_type ? `line:${d.line_type}` : '',
  ].filter(Boolean) as string[];
  return {
    provider,
    query: phone,
    ok: true,
    hits,
    rawSummary: `valid=${valid} country=${d.country_name ?? 'n/a'} carrier=${d.carrier ?? 'n/a'}`,
    entities: [
      {
        id: id('ent'),
        name: String(d.international_format || phone),
        type: 'phone',
        identifiers: [phone, String(d.international_format || ''), String(d.local_format || '')].filter(Boolean),
        confidence: 'POSSIBLE',
        notes: `Numverify: ${hits.join(', ')}`,
      },
    ],
    evidence: [
      {
        id: id('ev'),
        title: `Numverify phone check`,
        url: 'https://numverify.com',
        tags: ['numverify', 'phone'],
        confidence: 'POSSIBLE',
        attachments: [],
      },
    ],
    provenance: [
      {
        id: id('prov'),
        claim: `Numverify validation for ${phone}: ${valid ? 'valid' : 'invalid'}`,
        source: 'Numverify API',
        method: 'validate',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** AbuseIPDB IP reputation. */
export async function lookupAbuseIp(ip: string): Promise<ProviderLookupResult> {
  const key = env('ABUSEIPDB_API_KEY');
  const provider = 'abuseipdb';
  if (!key) {
    return {
      provider,
      query: ip,
      ok: false,
      error: 'ABUSEIPDB_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
  const { ok, data } = await fetchJson(url, {
    headers: { Key: key, Accept: 'application/json' },
  });
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: ip,
      ok: false,
      error: 'AbuseIPDB failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const score = d.abuseConfidenceScore;
  const hits = [
    score != null ? `abuseScore:${score}` : '',
    d.isp ? `isp:${d.isp}` : '',
    d.countryCode ? `cc:${d.countryCode}` : '',
    d.usageType ? `usage:${d.usageType}` : '',
  ].filter(Boolean) as string[];
  return {
    provider,
    query: ip,
    ok: true,
    hits,
    rawSummary: `abuseScore=${score ?? 'n/a'} isp=${d.isp ?? 'n/a'}`,
    entities: [
      {
        id: id('ent'),
        name: ip,
        type: 'ip',
        identifiers: [ip, ...(d.isp ? [String(d.isp)] : [])],
        confidence: 'POSSIBLE',
        notes: `AbuseIPDB score ${score ?? 'n/a'}`,
      },
    ],
    evidence: [
      {
        id: id('ev'),
        title: `AbuseIPDB check: score ${score ?? 'n/a'}`,
        url: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
        tags: ['abuseipdb', 'ip'],
        confidence: 'POSSIBLE',
        attachments: [],
      },
    ],
    provenance: [
      {
        id: id('prov'),
        claim: `AbuseIPDB reports score ${score ?? 'n/a'} for ${ip}`,
        source: 'AbuseIPDB API',
        method: 'check',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** Shodan host lookup. */
export async function lookupShodan(ip: string): Promise<ProviderLookupResult> {
  const key = env('SHODAN_API_KEY');
  const provider = 'shodan';
  if (!key) {
    return {
      provider,
      query: ip,
      ok: false,
      error: 'SHODAN_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
  const { ok, data } = await fetchJson(url);
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: ip,
      ok: false,
      error: 'Shodan host lookup failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const d = data as Record<string, unknown>;
  const ports = Array.isArray(d.ports) ? (d.ports as number[]) : [];
  const hostnames = Array.isArray(d.hostnames) ? (d.hostnames as string[]) : [];
  const org = d.org ? String(d.org) : '';
  const hits = [
    ...ports.map((p) => `port:${p}`),
    ...hostnames.slice(0, 5).map((h) => `host:${h}`),
    org ? `org:${org}` : '',
  ].filter(Boolean);
  return {
    provider,
    query: ip,
    ok: true,
    hits,
    rawSummary: `ports=${ports.join(',')} hostnames=${hostnames.slice(0, 3).join(',')}`,
    entities: [
      {
        id: id('ent'),
        name: ip,
        type: 'ip',
        identifiers: [ip, ...hostnames.slice(0, 5), ...(org ? [org] : [])],
        confidence: 'POSSIBLE',
        notes: `Shodan: ${ports.length} open port(s)`,
      },
    ],
    evidence: [
      {
        id: id('ev'),
        title: `Shodan host ${ip}`,
        url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
        tags: ['shodan', 'ip'],
        confidence: 'POSSIBLE',
        attachments: [],
      },
    ],
    provenance: [
      {
        id: id('prov'),
        claim: `Shodan reports ${ports.length} open port(s) on ${ip}`,
        source: 'Shodan API',
        method: 'host',
        confidence: 'POSSIBLE',
      },
    ],
  };
}

/** VirusTotal domain report. */
export async function lookupVirusTotalDomain(domain: string): Promise<ProviderLookupResult> {
  const key = env('VIRUSTOTAL_API_KEY');
  const provider = 'virustotal-domain';
  if (!key) {
    return {
      provider,
      query: domain,
      ok: false,
      error: 'VIRUSTOTAL_API_KEY not configured',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
  const { ok, data } = await fetchJson(url, {
    headers: { 'x-apikey': key },
  });
  if (!ok || !data || typeof data !== 'object') {
    return {
      provider,
      query: domain,
      ok: false,
      error: 'VirusTotal domain failed',
      hits: [],
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  const root = data as { data?: { attributes?: Record<string, unknown> } };
  const attrs = root.data?.attributes || {};
  const stats = (attrs.last_analysis_stats as Record<string, number>) || {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const hits = [
    `malicious:${malicious}`,
    `suspicious:${suspicious}`,
    attrs.registrar ? `registrar:${attrs.registrar}` : '',
  ].filter(Boolean) as string[];
  return {
    provider,
    query: domain,
    ok: true,
    hits,
    rawSummary: `VT malicious=${malicious} suspicious=${suspicious}`,
    entities: [
      {
        id: id('ent'),
        name: domain,
        type: 'domain',
        identifiers: [domain],
        confidence: 'POSSIBLE',
        notes: `VirusTotal: ${malicious} malicious / ${suspicious} suspicious`,
      },
    ],
    evidence: [
      {
        id: id('ev'),
        title: `VirusTotal domain ${domain}`,
        url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`,
        tags: ['virustotal', 'domain'],
        confidence: 'POSSIBLE',
        attachments: [],
      },
    ],
    provenance: [
      {
        id: id('prov'),
        claim: `VirusTotal last_analysis_stats for ${domain}: malicious=${malicious}`,
        source: 'VirusTotal API v3',
        method: 'domains',
        confidence: 'POSSIBLE',
      },
    ],
  };
}
