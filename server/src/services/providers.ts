/**
 * Live OSINT provider calls. Returns only data from the upstream API.
 * No synthetic/sample profiles. Findings use confidence Low until analyst verifies.
 *
 * Env keys (aliases accepted):
 *   HIBP_API_KEY
 *   HUNTER_API_KEY | HUNTERIO_API_KEY
 *   NUMVERIFY_API_KEY
 *   ABUSEIPDB_API_KEY | ABUSEPDB_API_KEY
 *   SHODAN_API_KEY
 *   VIRUSTOTAL_API_KEY
 */

import { randomUUID } from 'node:crypto';

export type Confidence = 'High' | 'Medium' | 'Low' | 'Unverified';

export interface ProviderEntity {
  id: string;
  name: string;
  type: string;
  identifiers: string[];
  confidence: Confidence;
  notes: string;
}

export interface ProviderEvidence {
  id: string;
  title: string;
  url: string;
  archiveUrl: string;
  tags: string[];
  confidence: Confidence;
  entityIds: string[];
  notes: string;
  eventDate: string;
  date: string;
  attachments: { name: string; type: string; dataUrl: string }[];
}

export interface ProviderProvenance {
  id: string;
  entityId: string;
  evidenceId: string;
  claim: string;
  notes: string;
}

export interface ProviderHit {
  title: string;
  url: string;
  detail: string;
  tags: string[];
}

export interface ProviderLookupResult {
  provider: string;
  query: string;
  queryType: string;
  configured: boolean;
  ok: boolean;
  error?: string;
  hits: ProviderHit[];
  rawSummary: string;
  entities: ProviderEntity[];
  evidence: ProviderEvidence[];
  provenance: ProviderProvenance[];
}

function id(prefix: string) {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function env(...keys: string[]): string | undefined {
  for (const key of keys) {
    const v = process.env[key]?.trim();
    if (v) return v;
  }
  return undefined;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function emptyResult(
  provider: string,
  query: string,
  queryType: string,
  error: string,
  configured = false
): ProviderLookupResult {
  return {
    provider,
    query,
    queryType,
    configured,
    ok: false,
    error,
    hits: [],
    rawSummary: error,
    entities: [],
    evidence: [],
    provenance: [],
  };
}

async function fetchJson(
  url: string,
  init?: RequestInit
): Promise<{ ok: boolean; status: number; data: unknown; text: string }> {
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.headers || {}),
    },
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text.slice(0, 800) };
  }
  return { ok: res.ok, status: res.status, data, text };
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

function makeProv(entityId: string, evidenceId: string, claim: string, notes = ''): ProviderProvenance {
  return { id: id('prov'), entityId, evidenceId, claim, notes };
}

export async function lookupHibp(email: string): Promise<ProviderLookupResult> {
  const key = env('HIBP_API_KEY');
  const provider = 'hibp';
  const queryType = 'email';
  if (!key) return emptyResult(provider, email, queryType, 'HIBP_API_KEY not configured');
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const { ok, status, data } = await fetchJson(url, {
    headers: { 'hibp-api-key': key, 'user-agent': 'osint-workbench-platform' },
  });
  if (status === 404) {
    const entity = makeEntity(email, 'email', [email], 'HIBP: no breaches reported');
    return {
      provider, query: email, queryType, configured: true, ok: true, hits: [],
      rawSummary: 'No breaches reported for this email.',
      entities: [entity], evidence: [],
      provenance: [makeProv(entity.id, '', `HIBP reports no breaches for ${email}`, 'HIBP API v3')],
    };
  }
  if (status === 401 || status === 403) {
    return emptyResult(provider, email, queryType, `HIBP auth failed (HTTP ${status}) — check HIBP_API_KEY`, true);
  }
  if (!ok || !Array.isArray(data)) {
    return emptyResult(provider, email, queryType, `HIBP HTTP ${status}`, true);
  }
  const breaches = data as Array<Record<string, unknown>>;
  const titles = breaches.map((b) => String(b.Name || b.Title || 'unknown')).filter(Boolean);
  const entity = makeEntity(email, 'email', [email, ...titles.map((t) => `breach:${t}`)], `Appears in ${titles.length} HIBP breach(es)`);
  const evidence = titles.map((t) =>
    makeEvidence(`HIBP breach: ${t}`, `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(t)}`, ['hibp', 'breach'], entity.id, `Breach name: ${t}`)
  );
  return {
    provider, query: email, queryType, configured: true, ok: true,
    hits: titles.map((t) => ({ title: t, url: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(t)}`, detail: 'breach', tags: ['hibp', 'breach'] })),
    rawSummary: `${titles.length} breach(es): ${titles.slice(0, 12).join(', ')}${titles.length > 12 ? '…' : ''}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0]?.id ?? '', `Email ${email} listed in ${titles.length} HIBP breach(es)`, 'HIBP API v3')],
  };
}

export async function lookupHunterEmail(email: string): Promise<ProviderLookupResult> {
  const key = env('HUNTER_API_KEY', 'HUNTERIO_API_KEY');
  const provider = 'hunter-email';
  const queryType = 'email';
  if (!key) return emptyResult(provider, email, queryType, 'HUNTER_API_KEY / HUNTERIO_API_KEY not configured');
  const url = `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${encodeURIComponent(key)}`;
  const { ok, status, data } = await fetchJson(url);
  if (status === 401) return emptyResult(provider, email, queryType, 'Hunter auth failed — check API key', true);
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, email, queryType, `Hunter email verifier failed (HTTP ${status})`, true);
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const result = String(d.result || d.status || '');
  const score = d.score;
  const sources = Array.isArray(d.sources) ? (d.sources as Array<Record<string, unknown>>) : [];
  const domain = d.domain ? String(d.domain) : '';
  const entity = makeEntity(email, 'email', [email, domain].filter(Boolean), `Hunter verifier: ${result || 'n/a'} (score ${score ?? 'n/a'})`);
  const hits: ProviderHit[] = [
    ...(result ? [{ title: `result:${result}`, url: 'https://hunter.io', detail: `score=${score ?? 'n/a'}`, tags: ['hunter'] }] : []),
    ...sources.slice(0, 8).map((s) => ({
      title: String(s.domain || s.uri || 'source'),
      url: String(s.uri || s.domain || 'https://hunter.io'),
      detail: String(s.extracted_on || ''),
      tags: ['hunter', 'source'],
    })),
  ];
  const evidence = [makeEvidence(`Hunter email verification: ${result || 'unknown'}`, 'https://hunter.io', ['hunter', 'email'], entity.id, `score=${score ?? 'n/a'} sources=${sources.length}`)];
  return {
    provider, query: email, queryType, configured: true, ok: true, hits,
    rawSummary: `Hunter result=${result || 'n/a'} score=${score ?? 'n/a'} sources=${sources.length}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0].id, `Hunter reports ${email} as ${result || 'unknown'}`, 'email-verifier')],
  };
}

export async function lookupHunterDomain(domain: string): Promise<ProviderLookupResult> {
  const key = env('HUNTER_API_KEY', 'HUNTERIO_API_KEY');
  const provider = 'hunter-domain';
  const queryType = 'domain';
  if (!key) return emptyResult(provider, domain, queryType, 'HUNTER_API_KEY / HUNTERIO_API_KEY not configured');
  const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${encodeURIComponent(key)}&limit=20`;
  const { ok, status, data } = await fetchJson(url);
  if (status === 401) return emptyResult(provider, domain, queryType, 'Hunter auth failed — check API key', true);
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, domain, queryType, `Hunter domain search failed (HTTP ${status})`, true);
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const emails = Array.isArray(d.emails) ? (d.emails as Array<Record<string, unknown>>) : [];
  const org = d.organization ? String(d.organization) : domain;
  const emailValues = emails.map((e) => String(e.value || '')).filter(Boolean);
  const orgEntity = makeEntity(org, 'organization', [domain], `Hunter domain search: ${emailValues.length} email(s)`);
  const emailEntities = emailValues.slice(0, 15).map((em) => {
    const row = emails.find((e) => String(e.value) === em) || {};
    const first = row.first_name ? String(row.first_name) : '';
    const last = row.last_name ? String(row.last_name) : '';
    const pos = row.position ? String(row.position) : '';
    return makeEntity(em, 'email', [em, domain, first, last].filter(Boolean), [pos, first, last].filter(Boolean).join(' · ') || `Found via Hunter on ${domain}`);
  });
  const hits: ProviderHit[] = emailValues.slice(0, 15).map((em) => ({
    title: em, url: `https://hunter.io/search/${encodeURIComponent(domain)}`, detail: 'email', tags: ['hunter', 'domain', 'email'],
  }));
  const evidence = emailValues.slice(0, 15).map((em, i) =>
    makeEvidence(`Hunter domain email: ${em}`, `https://hunter.io/search/${encodeURIComponent(domain)}`, ['hunter', 'domain', 'email'], emailEntities[i]?.id || orgEntity.id)
  );
  return {
    provider, query: domain, queryType, configured: true, ok: true, hits,
    rawSummary: `${emailValues.length} email(s) for ${domain}${org && org !== domain ? ` (${org})` : ''}`,
    entities: [orgEntity, ...emailEntities], evidence,
    provenance: [makeProv(orgEntity.id, evidence[0]?.id ?? '', `Hunter domain-search returned ${emailValues.length} email(s) for ${domain}`, 'domain-search')],
  };
}

export async function lookupNumverify(phone: string): Promise<ProviderLookupResult> {
  const key = env('NUMVERIFY_API_KEY');
  const provider = 'numverify';
  const queryType = 'phone';
  if (!key) return emptyResult(provider, phone, queryType, 'NUMVERIFY_API_KEY not configured');
  const url = `https://apilayer.net/api/validate?access_key=${encodeURIComponent(key)}&number=${encodeURIComponent(phone)}`;
  const { ok, status, data } = await fetchJson(url);
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, phone, queryType, `Numverify failed (HTTP ${status})`, true);
  }
  const d = data as Record<string, unknown>;
  if (d.success === false) {
    const err = (d.error as { info?: string })?.info || 'Numverify API error';
    return emptyResult(provider, phone, queryType, String(err), true);
  }
  const valid = Boolean(d.valid);
  const intl = String(d.international_format || phone);
  const country = d.country_name ? String(d.country_name) : '';
  const carrier = d.carrier ? String(d.carrier) : '';
  const line = d.line_type ? String(d.line_type) : '';
  const entity = makeEntity(intl, 'phone', [phone, intl, String(d.local_format || ''), country, carrier].filter(Boolean),
    `valid=${valid}; country=${country || 'n/a'}; carrier=${carrier || 'n/a'}; line=${line || 'n/a'}`);
  const hits: ProviderHit[] = [
    { title: valid ? 'valid' : 'invalid', url: 'https://numverify.com', detail: line || '', tags: ['numverify'] },
    ...(country ? [{ title: `country:${country}`, url: '', detail: String(d.country_code || ''), tags: ['numverify'] }] : []),
    ...(carrier ? [{ title: `carrier:${carrier}`, url: '', detail: '', tags: ['numverify'] }] : []),
  ];
  const evidence = [makeEvidence(`Numverify phone check: ${valid ? 'valid' : 'invalid'}`, 'https://numverify.com', ['numverify', 'phone'], entity.id, entity.notes)];
  return {
    provider, query: phone, queryType, configured: true, ok: true, hits,
    rawSummary: `valid=${valid} country=${country || 'n/a'} carrier=${carrier || 'n/a'} line=${line || 'n/a'}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0].id, `Numverify validation for ${phone}: ${valid ? 'valid' : 'invalid'}`, 'validate')],
  };
}

export async function lookupAbuseIp(ip: string): Promise<ProviderLookupResult> {
  const key = env('ABUSEIPDB_API_KEY', 'ABUSEPDB_API_KEY');
  const provider = 'abuseipdb';
  const queryType = 'ip';
  if (!key) return emptyResult(provider, ip, queryType, 'ABUSEIPDB_API_KEY / ABUSEPDB_API_KEY not configured');
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
  const { ok, status, data } = await fetchJson(url, { headers: { Key: key, Accept: 'application/json' } });
  if (status === 401 || status === 403) {
    return emptyResult(provider, ip, queryType, `AbuseIPDB auth failed (HTTP ${status})`, true);
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, ip, queryType, `AbuseIPDB failed (HTTP ${status})`, true);
  }
  const root = data as { data?: Record<string, unknown> };
  const d = root.data || {};
  const score = d.abuseConfidenceScore;
  const isp = d.isp ? String(d.isp) : '';
  const cc = d.countryCode ? String(d.countryCode) : '';
  const usage = d.usageType ? String(d.usageType) : '';
  const totalReports = d.totalReports != null ? String(d.totalReports) : '';
  const entity = makeEntity(ip, 'ip', [ip, isp, cc].filter(Boolean),
    `AbuseIPDB score=${score ?? 'n/a'}; reports=${totalReports || 'n/a'}; usage=${usage || 'n/a'}`);
  const hits: ProviderHit[] = [
    ...(score != null ? [{ title: `abuseScore:${score}`, url: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, detail: `${totalReports} reports`, tags: ['abuseipdb'] }] : []),
    ...(isp ? [{ title: `isp:${isp}`, url: '', detail: usage, tags: ['abuseipdb'] }] : []),
    ...(cc ? [{ title: `cc:${cc}`, url: '', detail: '', tags: ['abuseipdb'] }] : []),
  ];
  const evidence = [makeEvidence(`AbuseIPDB check: score ${score ?? 'n/a'}`, `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, ['abuseipdb', 'ip'], entity.id, entity.notes)];
  return {
    provider, query: ip, queryType, configured: true, ok: true, hits,
    rawSummary: `abuseScore=${score ?? 'n/a'} isp=${isp || 'n/a'} cc=${cc || 'n/a'} reports=${totalReports || 'n/a'}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0].id, `AbuseIPDB reports score ${score ?? 'n/a'} for ${ip}`, 'check')],
  };
}

export async function lookupShodan(ip: string): Promise<ProviderLookupResult> {
  const key = env('SHODAN_API_KEY');
  const provider = 'shodan';
  const queryType = 'ip';
  if (!key) return emptyResult(provider, ip, queryType, 'SHODAN_API_KEY not configured');
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
  const { ok, status, data } = await fetchJson(url);
  if (status === 401) return emptyResult(provider, ip, queryType, 'Shodan auth failed — check SHODAN_API_KEY', true);
  if (status === 404) {
    return {
      provider, query: ip, queryType, configured: true, ok: true, hits: [],
      rawSummary: 'No Shodan data for this IP.',
      entities: [makeEntity(ip, 'ip', [ip], 'Shodan: no host record')], evidence: [], provenance: [],
    };
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, ip, queryType, `Shodan host lookup failed (HTTP ${status})`, true);
  }
  const d = data as Record<string, unknown>;
  const ports = Array.isArray(d.ports) ? (d.ports as number[]) : [];
  const hostnames = Array.isArray(d.hostnames) ? (d.hostnames as string[]) : [];
  const org = d.org ? String(d.org) : '';
  const isp = d.isp ? String(d.isp) : '';
  const os = d.os ? String(d.os) : '';
  const entity = makeEntity(ip, 'ip', [ip, ...hostnames.slice(0, 8), org, isp].filter(Boolean),
    `Shodan: ${ports.length} open port(s); os=${os || 'n/a'}; org=${org || 'n/a'}`);
  const hits: ProviderHit[] = [
    ...ports.map((p) => ({ title: `port:${p}`, url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`, detail: '', tags: ['shodan', 'port'] })),
    ...hostnames.slice(0, 8).map((h) => ({ title: `host:${h}`, url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`, detail: '', tags: ['shodan', 'hostname'] })),
    ...(org ? [{ title: `org:${org}`, url: '', detail: isp, tags: ['shodan'] }] : []),
  ];
  const evidence = [makeEvidence(`Shodan host ${ip}`, `https://www.shodan.io/host/${encodeURIComponent(ip)}`, ['shodan', 'ip'], entity.id, entity.notes)];
  return {
    provider, query: ip, queryType, configured: true, ok: true, hits,
    rawSummary: `ports=${ports.join(',') || 'none'} hostnames=${hostnames.slice(0, 5).join(',') || 'none'} org=${org || 'n/a'}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0].id, `Shodan reports ${ports.length} open port(s) on ${ip}`, 'host')],
  };
}

export async function lookupVirusTotalDomain(domain: string): Promise<ProviderLookupResult> {
  const key = env('VIRUSTOTAL_API_KEY');
  const provider = 'virustotal-domain';
  const queryType = 'domain';
  if (!key) return emptyResult(provider, domain, queryType, 'VIRUSTOTAL_API_KEY not configured');
  const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
  const { ok, status, data } = await fetchJson(url, { headers: { 'x-apikey': key } });
  if (status === 401 || status === 403) {
    return emptyResult(provider, domain, queryType, `VirusTotal auth failed (HTTP ${status})`, true);
  }
  if (!ok || !data || typeof data !== 'object') {
    return emptyResult(provider, domain, queryType, `VirusTotal domain failed (HTTP ${status})`, true);
  }
  const root = data as { data?: { attributes?: Record<string, unknown> } };
  const attrs = root.data?.attributes || {};
  const stats = (attrs.last_analysis_stats as Record<string, number>) || {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const registrar = attrs.registrar ? String(attrs.registrar) : '';
  const categories =
    attrs.categories && typeof attrs.categories === 'object'
      ? Object.values(attrs.categories as Record<string, string>).slice(0, 5)
      : [];
  const entity = makeEntity(domain, 'domain', [domain, registrar, ...categories].filter(Boolean),
    `VirusTotal: malicious=${malicious} suspicious=${suspicious} harmless=${harmless}`);
  const hits: ProviderHit[] = [
    { title: `malicious:${malicious}`, url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, detail: `suspicious=${suspicious}`, tags: ['virustotal'] },
    { title: `suspicious:${suspicious}`, url: '', detail: '', tags: ['virustotal'] },
    ...(registrar ? [{ title: `registrar:${registrar}`, url: '', detail: '', tags: ['virustotal'] }] : []),
    ...categories.map((c) => ({ title: `cat:${c}`, url: '', detail: '', tags: ['virustotal', 'category'] })),
  ];
  const evidence = [makeEvidence(`VirusTotal domain ${domain}`, `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, ['virustotal', 'domain'], entity.id, entity.notes)];
  return {
    provider, query: domain, queryType, configured: true, ok: true, hits,
    rawSummary: `VT malicious=${malicious} suspicious=${suspicious} harmless=${harmless}${registrar ? ` registrar=${registrar}` : ''}`,
    entities: [entity], evidence,
    provenance: [makeProv(entity.id, evidence[0].id, `VirusTotal last_analysis_stats for ${domain}: malicious=${malicious}`, 'domains v3')],
  };
}
