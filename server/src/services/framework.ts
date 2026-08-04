/**
 * OSINT Framework integration — categorized tool directory + provider key status.
 * Inspired by osintframework.com taxonomy.
 */

export type ToolFlag = 'free' | 'freemium' | 'paid' | 'tool' | 'dork';
export type Opsec = 'passive' | 'active' | 'unknown';

export type FrameworkTool = {
  id: string;
  name: string;
  description: string;
  url: string;
  urlTemplate?: string;
  flag: ToolFlag;
  opsec: Opsec;
  providerId?: string;
};

export type FrameworkCategory = {
  id: string;
  name: string;
  description: string;
  tools: FrameworkTool[];
};

export type ProviderStatus = {
  id: string;
  name: string;
  category: string;
  envKey: string;
  configured: boolean;
  endpoint?: string;
};

export const FRAMEWORK_CATEGORIES: FrameworkCategory[] = [
  {
    id: 'username',
    name: 'Username',
    description: 'Hunt accounts and handles across platforms.',
    tools: [
      { id: 'sherlock', name: 'Sherlock (in-app)', description: 'Username enumeration via server (CLI or Node fallback).', url: '/api/scan/sherlock', flag: 'tool', opsec: 'active', providerId: 'sherlock' },
      { id: 'whatsmyname', name: 'WhatsMyName', description: 'Username presence checks across many sites.', url: 'https://whatsmyname.app/', urlTemplate: 'https://whatsmyname.app/?q={q}', flag: 'free', opsec: 'active' },
      { id: 'namechk', name: 'Namechk', description: 'Username availability across social networks.', url: 'https://namechk.com/', flag: 'freemium', opsec: 'active' },
    ],
  },
  {
    id: 'email',
    name: 'Email Address',
    description: 'Breach data, ownership, and email reputation.',
    tools: [
      { id: 'hibp', name: 'Have I Been Pwned', description: 'Breach exposure for an email address.', url: 'https://haveibeenpwned.com/', urlTemplate: 'https://haveibeenpwned.com/account/{q}', flag: 'freemium', opsec: 'passive', providerId: 'hibp' },
      { id: 'hunterio', name: 'Hunter.io', description: 'Email finder and verifier for domains.', url: 'https://hunter.io/', flag: 'freemium', opsec: 'passive', providerId: 'hunterio' },
      { id: 'leakcheck', name: 'LeakCheck', description: 'Leak and breach search.', url: 'https://leakcheck.io/', flag: 'paid', opsec: 'passive', providerId: 'leakcheck' },
      { id: 'epieos', name: 'Epieos', description: 'Email and phone OSINT portal.', url: 'https://epieos.com/', flag: 'freemium', opsec: 'passive' },
    ],
  },
  {
    id: 'domain',
    name: 'Domain Name',
    description: 'WHOIS, DNS, certificates, subdomains, reputation.',
    tools: [
      { id: 'securitytrails', name: 'SecurityTrails', description: 'Historical DNS and domain intelligence.', url: 'https://securitytrails.com/', urlTemplate: 'https://securitytrails.com/domain/{q}/dns', flag: 'freemium', opsec: 'passive', providerId: 'securitytrails' },
      { id: 'whoisxml', name: 'WhoisXML API', description: 'WHOIS and domain data API.', url: 'https://whois.whoisxmlapi.com/', flag: 'freemium', opsec: 'passive', providerId: 'whoisxml' },
      { id: 'crtsh', name: 'crt.sh', description: 'Certificate transparency subdomain discovery.', url: 'https://crt.sh/', urlTemplate: 'https://crt.sh/?q={q}', flag: 'free', opsec: 'passive' },
      { id: 'urlscan', name: 'urlscan.io', description: 'URL and domain scan / screenshot.', url: 'https://urlscan.io/', urlTemplate: 'https://urlscan.io/search/#domain:{q}', flag: 'freemium', opsec: 'active', providerId: 'urlscan' },
      { id: 'virustotal-domain', name: 'VirusTotal (domain)', description: 'Domain reputation and relations.', url: 'https://www.virustotal.com/', urlTemplate: 'https://www.virustotal.com/gui/domain/{q}', flag: 'freemium', opsec: 'passive', providerId: 'virustotal' },
    ],
  },
  {
    id: 'ip',
    name: 'IP Address',
    description: 'Hosting, ports, geolocation, abuse reputation.',
    tools: [
      { id: 'shodan', name: 'Shodan', description: 'Internet-wide device and service search.', url: 'https://www.shodan.io/', urlTemplate: 'https://www.shodan.io/host/{q}', flag: 'freemium', opsec: 'passive', providerId: 'shodan' },
      { id: 'abuseipdb', name: 'AbuseIPDB', description: 'IP abuse reports and confidence scores.', url: 'https://www.abuseipdb.com/', urlTemplate: 'https://www.abuseipdb.com/check/{q}', flag: 'freemium', opsec: 'passive', providerId: 'abuseipdb' },
      { id: 'pulsedive', name: 'Pulsedive', description: 'Threat intelligence on IPs and indicators.', url: 'https://pulsedive.com/', flag: 'freemium', opsec: 'passive', providerId: 'pulsedive' },
    ],
  },
  {
    id: 'search',
    name: 'Search Engines',
    description: 'General and specialized web search.',
    tools: [
      { id: 'serp', name: 'SerpAPI', description: 'Structured Google/Bing search results.', url: 'https://serpapi.com/', flag: 'paid', opsec: 'passive', providerId: 'serp' },
      { id: 'google-cse', name: 'Google Custom Search', description: 'Programmable Search Engine.', url: 'https://programmablesearchengine.google.com/', flag: 'freemium', opsec: 'passive', providerId: 'google_cse' },
      { id: 'wayback', name: 'Wayback Machine', description: 'Archived copies of web pages.', url: 'https://web.archive.org/', urlTemplate: 'https://web.archive.org/web/*/{q}', flag: 'free', opsec: 'passive' },
    ],
  },
  {
    id: 'social',
    name: 'Social & Media',
    description: 'Social networks and video platforms.',
    tools: [
      { id: 'youtube', name: 'YouTube Data API', description: 'Channel and video metadata.', url: 'https://developers.google.com/youtube/v3', flag: 'freemium', opsec: 'passive', providerId: 'youtube' },
      { id: 'socialsignal', name: 'Social Signal', description: 'Social signal / presence lookups.', url: 'https://www.socialsignal.com/', flag: 'paid', opsec: 'unknown', providerId: 'socialsignal' },
    ],
  },
  {
    id: 'phone',
    name: 'Telephone',
    description: 'Number validation and carrier data.',
    tools: [
      { id: 'numverify', name: 'Numverify', description: 'Phone number validation and location.', url: 'https://numverify.com/', flag: 'freemium', opsec: 'passive', providerId: 'numverify' },
    ],
  },
  {
    id: 'crypto',
    name: 'Digital Currency',
    description: 'Blockchain explorers and address intel.',
    tools: [
      { id: 'etherscan', name: 'Etherscan', description: 'Ethereum address and transaction lookup.', url: 'https://etherscan.io/', urlTemplate: 'https://etherscan.io/address/{q}', flag: 'freemium', opsec: 'passive', providerId: 'etherscan' },
    ],
  },
  {
    id: 'people',
    name: 'People Search',
    description: 'Identity resolution and people data.',
    tools: [
      { id: 'peopledatalabs', name: 'People Data Labs', description: 'Person and company enrichment APIs.', url: 'https://www.peopledatalabs.com/', flag: 'paid', opsec: 'passive', providerId: 'peopledatalabs' },
    ],
  },
  {
    id: 'scrape',
    name: 'Collection / Scraping',
    description: 'Structured collection helpers (use within ToS).',
    tools: [
      { id: 'apify', name: 'Apify', description: 'Actors and web automation.', url: 'https://apify.com/', flag: 'freemium', opsec: 'active', providerId: 'apify' },
      { id: 'scraperapi', name: 'ScraperAPI', description: 'Proxy scraping gateway.', url: 'https://www.scraperapi.com/', flag: 'paid', opsec: 'active', providerId: 'scraperapi' },
    ],
  },
  {
    id: 'ai',
    name: 'AI Assist (analysis only)',
    description: 'Summaries and hypotheses — never auto-VERIFIED.',
    tools: [
      { id: 'openai', name: 'OpenAI', description: 'Case summary / next-step suggestions.', url: 'https://platform.openai.com/', flag: 'paid', opsec: 'unknown', providerId: 'openai' },
      { id: 'grok', name: 'Grok / xAI', description: 'Analysis assist via xAI API.', url: 'https://x.ai/', flag: 'paid', opsec: 'unknown', providerId: 'grok' },
      { id: 'gemini', name: 'Google Gemini', description: 'Analysis assist via Gemini API.', url: 'https://ai.google.dev/', flag: 'freemium', opsec: 'unknown', providerId: 'gemini' },
      { id: 'claude', name: 'Anthropic Claude', description: 'Analysis assist via Claude API.', url: 'https://www.anthropic.com/', flag: 'paid', opsec: 'unknown', providerId: 'claude' },
      { id: 'openrouter', name: 'OpenRouter', description: 'Multi-model router for analysis prompts.', url: 'https://openrouter.ai/', flag: 'paid', opsec: 'unknown', providerId: 'openrouter' },
    ],
  },
];

const PROVIDER_ENV: Record<string, { name: string; category: string; envKey: string; endpoint?: string }> = {
  sherlock: { name: 'Sherlock', category: 'username', envKey: '', endpoint: '/api/scan/sherlock' },
  hibp: { name: 'Have I Been Pwned', category: 'email', envKey: 'HIBP_API_KEY' },
  hunterio: { name: 'Hunter.io', category: 'email', envKey: 'HUNTER_API_KEY' },
  leakcheck: { name: 'LeakCheck', category: 'email', envKey: 'LEAKCHECK_API_KEY' },
  securitytrails: { name: 'SecurityTrails', category: 'domain', envKey: 'SECURITYTRAILS_API_KEY' },
  whoisxml: { name: 'WhoisXML', category: 'domain', envKey: 'WHOISXML_API_KEY' },
  urlscan: { name: 'urlscan.io', category: 'domain', envKey: 'URLSCAN_API_KEY' },
  virustotal: { name: 'VirusTotal', category: 'domain', envKey: 'VIRUSTOTAL_API_KEY' },
  shodan: { name: 'Shodan', category: 'ip', envKey: 'SHODAN_API_KEY' },
  abuseipdb: { name: 'AbuseIPDB', category: 'ip', envKey: 'ABUSEIPDB_API_KEY' },
  pulsedive: { name: 'Pulsedive', category: 'ip', envKey: 'PULSEDIVE_API_KEY' },
  serp: { name: 'SerpAPI', category: 'search', envKey: 'SERP_API_KEY' },
  google_cse: { name: 'Google Custom Search', category: 'search', envKey: 'CLOUD_CUSTOM_SEARCH_API' },
  youtube: { name: 'YouTube Data', category: 'social', envKey: 'YOUTUBE_DATA_API_KEY' },
  socialsignal: { name: 'Social Signal', category: 'social', envKey: 'SOCIALSIGNAL_API_KEY' },
  numverify: { name: 'Numverify', category: 'phone', envKey: 'NUMVERIFY_API_KEY' },
  etherscan: { name: 'Etherscan', category: 'crypto', envKey: 'ETHERSCAN_API_KEY' },
  peopledatalabs: { name: 'People Data Labs', category: 'people', envKey: 'PEOPLEDATALABS_API_KEY' },
  apify: { name: 'Apify', category: 'scrape', envKey: 'APIFY_API_KEY' },
  scraperapi: { name: 'ScraperAPI', category: 'scrape', envKey: 'SCRAPER_API_KEY' },
  openai: { name: 'OpenAI', category: 'ai', envKey: 'OPENAI_API_KEY' },
  grok: { name: 'Grok / xAI', category: 'ai', envKey: 'GROK_API_KEY' },
  gemini: { name: 'Gemini', category: 'ai', envKey: 'GEMINI_API_KEY' },
  claude: { name: 'Claude', category: 'ai', envKey: 'CLAUDE_API_KEY' },
  openrouter: { name: 'OpenRouter', category: 'ai', envKey: 'OPENROUTER_API_KEY' },
};

const ENV_ALIASES: Record<string, string[]> = {
  HUNTER_API_KEY: ['HUNTER_API_KEY', 'HUNTERIO_API_KEY'],
  ABUSEIPDB_API_KEY: ['ABUSEIPDB_API_KEY', 'ABUSEPDB_API_KEY'],
};

function cleanEnvValue(raw: string | undefined): string | undefined {
  if (raw == null) return undefined;
  let v = raw.trim();
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }
  if (!v || v === '-' || v.endsWith('_API_KEY') || v.endsWith('_')) return undefined;
  return v;
}

function isConfigured(envKey: string): boolean {
  if (!envKey) return true;
  const keys = ENV_ALIASES[envKey] || [envKey];
  for (const k of keys) {
    if (cleanEnvValue(process.env[k])) return true;
  }
  return false;
}

export function getProviderStatuses(): ProviderStatus[] {
  return Object.entries(PROVIDER_ENV).map(([id, meta]) => ({
    id,
    name: meta.name,
    category: meta.category,
    envKey: meta.envKey || '(none)',
    configured: isConfigured(meta.envKey),
    endpoint: meta.endpoint,
  }));
}

export function getFrameworkCatalog() {
  const providers = getProviderStatuses();
  const configuredIds = new Set(providers.filter((p) => p.configured).map((p) => p.id));
  const categories = FRAMEWORK_CATEGORIES.map((cat) => ({
    ...cat,
    tools: cat.tools.map((t) => ({
      ...t,
      inAppReady: t.providerId ? configuredIds.has(t.providerId) : false,
      openUrl: t.url,
    })),
  }));
  return {
    source: 'osint-workbench-framework',
    inspiredBy: 'https://osintframework.com/',
    note: 'Directory + key status. External tools open in a new tab. In-app providers use server keys. Findings stay POSSIBLE until verified.',
    categories,
    providers,
    summary: {
      categories: categories.length,
      tools: categories.reduce((n, c) => n + c.tools.length, 0),
      providersConfigured: providers.filter((p) => p.configured).length,
      providersTotal: providers.length,
    },
  };
}

export function buildToolUrl(tool: FrameworkTool, query: string): string {
  const q = encodeURIComponent(query.trim());
  if (tool.urlTemplate && query.trim()) {
    return tool.urlTemplate.replace(/\{q\}/g, q);
  }
  return tool.url;
}
