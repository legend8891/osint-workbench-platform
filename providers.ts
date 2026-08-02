/**
 * Live OSINT provider calls. Returns only data from the upstream API.
 * No synthetic/sample profiles. Missing API key → explicit error, not fake hits.
 */

import { randomUUID } from 'node:crypto';
import type {
  Confidence,
  EntityRecord,
  EvidenceRecord,
  ProvenanceStep,
} from 'shared';

export type ProviderHit = {
  title: string;
  url: string;
  detail: string;
  tags: string[];
};

export type ProviderLookupResult = {
  provider: string;
  query: string;
  queryType: 'email' | 'username' | 'domain' | 'ip' | 'phone';
  configured: boolean;
  ok: boolean;
  error?: string;
  hits: ProviderHit[];
  rawSummary: string;
  entities: EntityRecord[];
  evidence: EvidenceRecord[];
  provenance: ProvenanceStep[];
};

function requireKey(name: string): string | null {
  const v = process.env[name]?.trim();
  if (!v || v === '-' || v.endsWith('_')) return null;
  return v;
}

function nowDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function pack(
  provider: string,
  query: string,
  queryType: ProviderLookupResult['queryType'],
  hits: ProviderHit[],
  entityType: string,
  confidence: Confidence,
  notes: string
): ProviderLookupResult {
  const entityId = `entity-${provider}-${randomUUID().slice(0, 8)}`;
  const entity: EntityRecord = {
    id: entityId,
    name: query,
    type: entityType,
    confidence,
    identifiers: [query, ...hits.map((h) => h.url).filter(Boolean)],
    notes,
  };

  const evidence: EvidenceRecord[] = hits.map((h) => {
    const id = `ev-${provider}-${randomUUID().slice(0, 8)}`;
    return {
      id,
      title: h.title,
      url: h.url || '',
      archiveUrl: h.url
        ? `https://web.archive.org/web/*/${encodeURIComponent(h.url)}`
        : '',
      confidence,
      entityIds: [entityId],
      notes: h.detail,
      tags: [...h.tags, provider, 'live-api'],
      eventDate: nowDate(),
      date: nowDate(),
      attachments: [],
    };
  });

  const provenance: ProvenanceStep[] = evidence.map((ev) => ({
    id: `prov-${ev.id}`,
    entityId,
    evidenceId: ev.id,
    claim: `${provider} returned data for "${query}". Treat as POSSIBLE until independently verified.`,
    notes: `Source: ${provider} live API`,
  }));

  return {
    provider,
    query,
    queryType,
    configured: true,
    ok: true,
    hits,
    rawSummary: `${hits.length} result(s) from ${provider}`,
    entities: hits.length ? [entity] : [],
    evidence,
    provenance,
  };
}

function notConfigured(
  provider: string,
  query: string,
  queryType: ProviderLookupResult['queryType'],
  envKey: string
): ProviderLookupResult {
  return {
    provider,
    query,
    queryType,
    configured: false,
    ok: false,
    error: `${envKey} is not set on the server`,
    hits: [],
    rawSummary: '',
    entities: [],
    evidence: [],
    provenance: [],
  };
}

function fail(
  provider: string,
  query: string,
  queryType: ProviderLookupResult['queryType'],
  message: string
): ProviderLookupResult {
  return {
    provider,
    query,
    queryType,
    configured: true,
    ok: false,
    error: message,
    hits: [],
    rawSummary: '',
    entities: [],
    evidence: [],
    provenance: [],
  };
}

/** Have I Been Pwned — breached account (email). */
export async function lookupHibp(email: string): Promise<ProviderLookupResult> {
  const key = requireKey('HIBP_API_KEY');
  const q = email.trim().toLowerCase();
  if (!key) return notConfigured('hibp', q, 'email', 'HIBP_API_KEY');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) {
    return fail('hibp', q, 'email', 'Invalid email format');
  }

  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(q)}?truncateResponse=false`;
  const res = await fetch(url, {
    headers: {
      'hibp-api-key': key,
      'User-Agent': 'OSINT-Workbench/0.9',
    },
  });

  if (res.status === 404) {
    return {
      provider: 'hibp',
      query: q,
      queryType: 'email',
      configured: true,
      ok: true,
      hits: [],
      rawSummary: 'No breaches found for this account (HTTP 404)',
      entities: [],
      evidence: [],
      provenance: [],
    };
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('hibp', q, 'email', `HIBP HTTP ${res.status}: ${text.slice(0, 200)}`);
  }

  const breaches = (await res.json()) as Array<{
    Name?: string;
    Title?: string;
    Domain?: string;
    BreachDate?: string;
    Description?: string;
    DataClasses?: string[];
    IsVerified?: boolean;
  }>;

  const hits: ProviderHit[] = (Array.isArray(breaches) ? breaches : []).map((b) => ({
    title: `Breach: ${b.Title || b.Name || 'Unknown'}`,
    url: b.Domain ? `https://${b.Domain}` : 'https://haveibeenpwned.com/',
    detail: [
      b.BreachDate ? `Date: ${b.BreachDate}` : '',
      b.IsVerified === false ? 'Unverified breach flag' : 'Verified breach flag',
      b.DataClasses?.length ? `Classes: ${b.DataClasses.join(', ')}` : '',
      b.Description ? b.Description.replace(/<[^>]+>/g, '').slice(0, 300) : '',
    ]
      .filter(Boolean)
      .join(' | '),
    tags: ['breach', 'hibp', b.Name || 'breach'].filter(Boolean),
  }));

  return pack(
    'hibp',
    q,
    'email',
    hits,
    'Email',
    hits.length ? 'Medium' : 'Low',
    hits.length
      ? `HIBP listed ${hits.length} breach(es). POSSIBLE exposure only — confirm with account owner.`
      : 'No breaches returned.'
  );
}

/** Hunter.io — email verifier. */
export async function lookupHunterEmail(email: string): Promise<ProviderLookupResult> {
  const key = requireKey('HUNTERIO_API_KEY');
  const q = email.trim().toLowerCase();
  if (!key) return notConfigured('hunterio', q, 'email', 'HUNTERIO_API_KEY');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) {
    return fail('hunterio', q, 'email', 'Invalid email format');
  }

  const url = `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(q)}&api_key=${encodeURIComponent(key)}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('hunterio', q, 'email', `Hunter HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const body = (await res.json()) as {
    data?: {
      status?: string;
      result?: string;
      score?: number;
      email?: string;
      regexp?: boolean;
      gibberish?: boolean;
      disposable?: boolean;
      webmail?: boolean;
      mx_records?: boolean;
      smtp_check?: boolean;
      sources?: Array<{ domain?: string; uri?: string }>;
    };
  };
  const d = body.data;
  if (!d) return fail('hunterio', q, 'email', 'Empty Hunter response');

  const hits: ProviderHit[] = [
    {
      title: `Hunter verify: ${d.result || d.status || 'unknown'}`,
      url: `https://hunter.io/email-verifier/${encodeURIComponent(q)}`,
      detail: [
        `score=${d.score ?? 'n/a'}`,
        `disposable=${d.disposable}`,
        `webmail=${d.webmail}`,
        `mx=${d.mx_records}`,
        `smtp=${d.smtp_check}`,
      ].join(' | '),
      tags: ['email-verify', 'hunter'],
    },
    ...(d.sources || []).slice(0, 10).map((s) => ({
      title: `Source: ${s.domain || 'unknown'}`,
      url: s.uri || (s.domain ? `https://${s.domain}` : ''),
      detail: 'Listed as public source by Hunter',
      tags: ['source', 'hunter'],
    })),
  ];

  return pack(
    'hunterio',
    q,
    'email',
    hits,
    'Email',
    d.result === 'deliverable' ? 'Medium' : 'Low',
    `Hunter result=${d.result || d.status}. POSSIBLE only.`
  );
}

/** Hunter.io — domain search (emails on domain). */
export async function lookupHunterDomain(domain: string): Promise<ProviderLookupResult> {
  const key = requireKey('HUNTERIO_API_KEY');
  const q = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!key) return notConfigured('hunterio', q, 'domain', 'HUNTERIO_API_KEY');

  const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(q)}&limit=10&api_key=${encodeURIComponent(key)}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('hunterio', q, 'domain', `Hunter HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const body = (await res.json()) as {
    data?: {
      domain?: string;
      organization?: string;
      emails?: Array<{
        value?: string;
        type?: string;
        confidence?: number;
        first_name?: string;
        last_name?: string;
        position?: string;
      }>;
    };
  };
  const emails = body.data?.emails || [];
  const hits: ProviderHit[] = emails.map((e) => ({
    title: e.value || 'email',
    url: e.value ? `mailto:${e.value}` : '',
    detail: [
      e.type,
      e.position,
      [e.first_name, e.last_name].filter(Boolean).join(' '),
      e.confidence != null ? `confidence=${e.confidence}` : '',
      body.data?.organization ? `org=${body.data.organization}` : '',
    ]
      .filter(Boolean)
      .join(' | '),
    tags: ['domain-email', 'hunter'],
  }));

  return pack(
    'hunterio',
    q,
    'domain',
    hits,
    'Domain',
    hits.length ? 'Medium' : 'Low',
    `Hunter domain-search returned ${hits.length} email(s). POSSIBLE only.`
  );
}

/** Numverify — phone validation. */
export async function lookupNumverify(phone: string): Promise<ProviderLookupResult> {
  const key = requireKey('NUMVERIFY_API_KEY');
  const q = phone.trim();
  if (!key) return notConfigured('numverify', q, 'phone', 'NUMVERIFY_API_KEY');

  const url = `http://apilayer.net/api/validate?access_key=${encodeURIComponent(key)}&number=${encodeURIComponent(q)}`;
  const res = await fetch(url);
  if (!res.ok) {
    return fail('numverify', q, 'phone', `Numverify HTTP ${res.status}`);
  }
  const d = (await res.json()) as {
    valid?: boolean;
    number?: string;
    local_format?: string;
    international_format?: string;
    country_name?: string;
    location?: string;
    carrier?: string;
    line_type?: string;
    error?: { info?: string };
  };
  if (d.error?.info) return fail('numverify', q, 'phone', d.error.info);

  const hits: ProviderHit[] = [
    {
      title: d.valid ? 'Valid number' : 'Invalid number',
      url: '',
      detail: [
        d.international_format || d.number,
        d.country_name,
        d.location,
        d.carrier,
        d.line_type,
      ]
        .filter(Boolean)
        .join(' | '),
      tags: ['phone', 'numverify'],
    },
  ];

  return pack(
    'numverify',
    q,
    'phone',
    hits,
    'Phone',
    d.valid ? 'Medium' : 'Low',
    'Numverify validation. POSSIBLE only.'
  );
}

/** AbuseIPDB — IP reputation. */
export async function lookupAbuseIp(ip: string): Promise<ProviderLookupResult> {
  const key = requireKey('ABUSEPDB_API_KEY');
  const q = ip.trim();
  if (!key) return notConfigured('abuseipdb', q, 'ip', 'ABUSEPDB_API_KEY');

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(q)}&maxAgeInDays=90&verbose`;
  const res = await fetch(url, {
    headers: { Key: key, Accept: 'application/json' },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('abuseipdb', q, 'ip', `AbuseIPDB HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const body = (await res.json()) as {
    data?: {
      ipAddress?: string;
      abuseConfidenceScore?: number;
      countryCode?: string;
      isp?: string;
      domain?: string;
      usageType?: string;
      totalReports?: number;
      lastReportedAt?: string;
    };
  };
  const d = body.data;
  if (!d) return fail('abuseipdb', q, 'ip', 'Empty AbuseIPDB response');

  const hits: ProviderHit[] = [
    {
      title: `Abuse confidence ${d.abuseConfidenceScore ?? 'n/a'}%`,
      url: `https://www.abuseipdb.com/check/${encodeURIComponent(q)}`,
      detail: [
        d.isp ? `ISP: ${d.isp}` : '',
        d.domain ? `Domain: ${d.domain}` : '',
        d.countryCode ? `CC: ${d.countryCode}` : '',
        d.usageType ? `Usage: ${d.usageType}` : '',
        d.totalReports != null ? `Reports: ${d.totalReports}` : '',
        d.lastReportedAt ? `Last: ${d.lastReportedAt}` : '',
      ]
        .filter(Boolean)
        .join(' | '),
      tags: ['ip', 'abuseipdb'],
    },
  ];

  return pack(
    'abuseipdb',
    q,
    'ip',
    hits,
    'IP',
    (d.abuseConfidenceScore ?? 0) >= 50 ? 'Medium' : 'Low',
    'AbuseIPDB check. POSSIBLE only.'
  );
}

/** VirusTotal — domain report (v3). */
export async function lookupVirusTotalDomain(domain: string): Promise<ProviderLookupResult> {
  const key = requireKey('VIRUSTOTAL_API_KEY');
  const q = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!key) return notConfigured('virustotal', q, 'domain', 'VIRUSTOTAL_API_KEY');

  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(q)}`;
  const res = await fetch(url, { headers: { 'x-apikey': key } });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('virustotal', q, 'domain', `VirusTotal HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const body = (await res.json()) as {
    data?: {
      attributes?: {
        last_analysis_stats?: Record<string, number>;
        reputation?: number;
        registrar?: string;
        categories?: Record<string, string>;
      };
    };
  };
  const a = body.data?.attributes;
  const stats = a?.last_analysis_stats || {};
  const hits: ProviderHit[] = [
    {
      title: `VT stats malicious=${stats.malicious ?? 0} suspicious=${stats.suspicious ?? 0}`,
      url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(q)}`,
      detail: [
        `harmless=${stats.harmless ?? 0}`,
        `undetected=${stats.undetected ?? 0}`,
        a?.reputation != null ? `reputation=${a.reputation}` : '',
        a?.registrar ? `registrar=${a.registrar}` : '',
        a?.categories ? `categories=${Object.values(a.categories).join(', ')}` : '',
      ]
        .filter(Boolean)
        .join(' | '),
      tags: ['domain', 'virustotal'],
    },
  ];

  return pack(
    'virustotal',
    q,
    'domain',
    hits,
    'Domain',
    (stats.malicious ?? 0) > 0 ? 'Medium' : 'Low',
    'VirusTotal domain report. POSSIBLE only.'
  );
}

/** Shodan — host lookup. */
export async function lookupShodan(ip: string): Promise<ProviderLookupResult> {
  const key = requireKey('SHODAN_API_KEY');
  const q = ip.trim();
  if (!key) return notConfigured('shodan', q, 'ip', 'SHODAN_API_KEY');

  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(q)}?key=${encodeURIComponent(key)}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return fail('shodan', q, 'ip', `Shodan HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const d = (await res.json()) as {
    ip_str?: string;
    org?: string;
    isp?: string;
    os?: string;
    ports?: number[];
    hostnames?: string[];
    country_name?: string;
    city?: string;
    data?: Array<{ port?: number; product?: string; banner?: string }>;
  };

  const hits: ProviderHit[] = [
    {
      title: `Shodan host ${d.ip_str || q}`,
      url: `https://www.shodan.io/host/${encodeURIComponent(q)}`,
      detail: [
        d.org ? `org=${d.org}` : '',
        d.isp ? `isp=${d.isp}` : '',
        d.os ? `os=${d.os}` : '',
        d.country_name || d.city
          ? `geo=${[d.city, d.country_name].filter(Boolean).join(', ')}`
          : '',
        d.ports?.length ? `ports=${d.ports.join(',')}` : '',
        d.hostnames?.length ? `hostnames=${d.hostnames.join(',')}` : '',
      ]
        .filter(Boolean)
        .join(' | '),
      tags: ['ip', 'shodan'],
    },
    ...(d.data || []).slice(0, 8).map((svc) => ({
      title: `Port ${svc.port ?? '?'}${svc.product ? ` — ${svc.product}` : ''}`,
      url: `https://www.shodan.io/host/${encodeURIComponent(q)}`,
      detail: (svc.banner || '').slice(0, 200),
      tags: ['service', 'shodan'],
    })),
  ];

  return pack(
    'shodan',
    q,
    'ip',
    hits,
    'IP',
    'Medium',
    'Shodan host data. POSSIBLE only.'
  );
}
