import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  CaseRecord,
  CorrelationHit,
  TimelineEvent,
  ProvenanceStep,
} from 'shared';
import { sampleCases, createEmptyCase } from '../store/sampleData';
import {
  buildCorrelationHits,
  downloadJson,
  exportBundleZip,
  exportHtmlReport,
  exportGraphML,
  runSherlockScan,
  mergeScanIntoCase,
  fetchFrameworkCatalog,
  launchFrameworkTool,
  lookupEmailBundle,
  lookupHunterDomain,
  lookupVirusTotalDomain,
  lookupShodan,
  lookupAbuseIp,
  lookupNumverify,
  lookupSpiderfoot,
  lookupFreeRecon,
  mergeProviderIntoCase,
  loadCases,
  saveCases,
  parseImportedCase,
  withUniqueId,
  sanitizeFilename,
  renameCase,
  deleteCase,
  promoteEntityConfidence,
  verifyEntity,
  unverifyEntity,
  removeEntity,
  promoteEvidenceConfidence,
  verifyEvidence,
  unverifyEvidence,
  removeEvidence,
  addRelationship,
  removeRelationship,
  type SherlockScanResult,
  type FrameworkCatalog,
  type ProviderLookupResult,
  type FreeReconResponse,
} from '../lib/workbench';

const tabs = [
  'cases',
  'lookup',
  'entities',
  'evidence',
  'analysis',
  'graph',
  'framework',
  'report',
] as const;
type Tab = (typeof tabs)[number];

type HealthInfo = {
  ok: boolean;
  version: string;
  providersConfigured: string[];
  providersMissing: string[];
  freeProviders: string[];
};

/** A provider hit is either a bare string or a structured object. */
type HitLike = string | { title?: string; url?: string; detail?: string; tags?: string[] };

const CONFIDENCE_CLASS: Record<string, string> = {
  High: 'badge badge-high',
  Medium: 'badge badge-medium',
  Low: 'badge badge-low',
  Unverified: 'badge badge-unverified',
};

function ConfidenceBadge({ value, verified }: { value: string; verified?: boolean }) {
  return (
    <span className={CONFIDENCE_CLASS[value] ?? 'badge'}>
      {value}
      {verified ? ' ✓' : ''}
    </span>
  );
}

const inputStyle = {
  flex: 1,
  minHeight: 44,
  padding: '0.75rem 1rem',
  borderRadius: 999,
  border: '1px solid rgba(0,0,0,.15)',
} as const;

export function App() {
  const [activeTab, setActiveTab] = useState<Tab>('cases');
  const [cases, setCases] = useState<CaseRecord[]>(() => {
    const stored = loadCases();
    return stored.length > 0 ? stored : sampleCases;
  });
  const [activeCaseId, setActiveCaseId] = useState<string>('');
  const [correlationHits, setCorrelationHits] = useState<CorrelationHit[]>([]);
  const [health, setHealth] = useState<HealthInfo | null>(null);

  const [sherlockInput, setSherlockInput] = useState('');
  const [sherlockBusy, setSherlockBusy] = useState(false);
  const [sherlockLog, setSherlockLog] = useState<string[]>([]);
  const [lastSherlock, setLastSherlock] = useState<SherlockScanResult[] | null>(null);
  const [framework, setFramework] = useState<FrameworkCatalog | null>(null);
  const [frameworkError, setFrameworkError] = useState<string | null>(null);
  const [frameworkQuery, setFrameworkQuery] = useState('');
  const [frameworkLoading, setFrameworkLoading] = useState(false);

  const [lookupEmail, setLookupEmail] = useState('');
  const [lookupDomain, setLookupDomain] = useState('');
  const [lookupIp, setLookupIp] = useState('');
  const [lookupPhone, setLookupPhone] = useState('');
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookupLog, setLookupLog] = useState<string[]>([]);
  const [lastProviders, setLastProviders] = useState<ProviderLookupResult[]>([]);

  // Free recon (no API key)
  const [freeTarget, setFreeTarget] = useState('');
  const [freeBusy, setFreeBusy] = useState(false);
  const [freeLog, setFreeLog] = useState<string[]>([]);
  const [lastFree, setLastFree] = useState<FreeReconResponse | null>(null);

  // SpiderFoot CLI
  const [sfTarget, setSfTarget] = useState('');
  const [sfBusy, setSfBusy] = useState(false);
  const [sfLog, setSfLog] = useState<string[]>([]);

  // Case management + relationship editor
  const [renameValue, setRenameValue] = useState('');
  const [relSource, setRelSource] = useState('');
  const [relTarget, setRelTarget] = useState('');
  const [relType, setRelType] = useState('');

  const [importError, setImportError] = useState<string | null>(null);
  const [storageWarning, setStorageWarning] = useState(false);
  const importInputRef = useRef<HTMLInputElement | null>(null);

  const hydrated = useRef(false);

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) ?? null,
    [cases, activeCaseId]
  );

  const stats = useMemo(() => {
    const attachments = cases.reduce(
      (count, c) => count + c.evidence.reduce((n, e) => n + e.attachments.length, 0),
      0
    );
    const verified =
      cases.reduce(
        (n, c) => n + c.entities.filter((e) => e.verified).length + c.evidence.filter((e) => e.verified).length,
        0
      );
    return { cases: cases.length, correlations: correlationHits.length, attachments, verified };
  }, [cases, correlationHits]);

  /* Persistence: hydrate once, then persist on every change. */
  useEffect(() => {
    if (!hydrated.current) {
      hydrated.current = true;
      return;
    }
    setStorageWarning(!saveCases(cases));
  }, [cases]);

  useEffect(() => {
    if (!activeCaseId && cases.length > 0) setActiveCaseId(cases[0].id);
  }, [activeCaseId, cases]);

  useEffect(() => {
    setCorrelationHits(buildCorrelationHits(cases));
  }, [cases]);

  useEffect(() => {
    fetch('/health')
      .then((r) => r.json())
      .then((d) => setHealth(d as HealthInfo))
      .catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    if (activeCase) setRenameValue(activeCase.name);
  }, [activeCaseId]); // eslint-disable-line react-hooks/exhaustive-deps

  function ensureCase(): CaseRecord {
    if (activeCase) return activeCase;
    return createEmptyCase();
  }

  function updateCase(next: CaseRecord) {
    setCases((prev) => {
      const exists = prev.some((c) => c.id === next.id);
      return exists ? prev.map((c) => (c.id === next.id ? next : c)) : [...prev, next];
    });
    setActiveCaseId(next.id);
  }

  function newCase() {
    const created = createEmptyCase(`Investigation ${cases.length + 1}`);
    setCases((prev) => [...prev, created]);
    setActiveCaseId(created.id);
    setActiveTab('lookup');
  }

  function handleDeleteCase(id: string) {
    const next = deleteCase(cases, id);
    setCases(next);
    if (activeCaseId === id) setActiveCaseId(next[0]?.id ?? '');
  }

  function handleRenameCase() {
    if (!activeCase) return;
    setCases(renameCase(cases, activeCase.id, renameValue));
  }

  async function handleImportFile(file: File | null | undefined) {
    if (!file) return;
    setImportError(null);
    try {
      const text = await file.text();
      const parsed = parseImportedCase(text);
      const record = withUniqueId(parsed, cases);
      setCases((prev) => [...prev, record]);
      setActiveCaseId(record.id);
      setActiveTab('cases');
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Failed to import case');
    } finally {
      if (importInputRef.current) importInputRef.current.value = '';
    }
  }

  async function loadFramework() {
    setFrameworkLoading(true);
    setFrameworkError(null);
    try {
      setFramework(await fetchFrameworkCatalog());
    } catch (err) {
      setFrameworkError(err instanceof Error ? err.message : 'Failed to load framework');
    } finally {
      setFrameworkLoading(false);
    }
  }

  async function handleSherlockScan() {
    const base = ensureCase();
    const usernames = sherlockInput
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 10);
    if (usernames.length === 0) {
      setSherlockLog(['Enter at least one username']);
      return;
    }
    setSherlockBusy(true);
    setSherlockLog([`Scanning ${usernames.join(', ')}…`]);
    try {
      const api = await runSherlockScan(usernames);
      setLastSherlock(api.results);
      updateCase(mergeScanIntoCase(base, api.results));
      setSherlockLog([
        `Mode: ${api.summary.mode}`,
        `Found: ${api.summary.totalFound} profile(s)`,
        ...api.results.flatMap((r) => r.notes),
      ]);
    } catch (err) {
      setSherlockLog([
        err instanceof Error ? err.message : 'Scan failed',
        'Check server / API keys / network',
      ]);
    } finally {
      setSherlockBusy(false);
    }
  }

  async function runFreeLookup() {
    const target = freeTarget.trim();
    if (!target) {
      setFreeLog(['Enter a domain, IP, email, or URL']);
      return;
    }
    const base = ensureCase();
    setFreeBusy(true);
    setFreeLog([`Free recon on ${target}…`]);
    try {
      const bundle = await lookupFreeRecon(target);
      setLastFree(bundle);
      updateCase(mergeProviderIntoCase(base, bundle.results));
      const providerLines = bundle.results.map((r) =>
        r.ok
          ? `${r.provider}: ${r.rawSummary || `${r.hits.length} hit(s)`} · entities=${r.entities.length} evidence=${r.evidence.length}`
          : `${r.provider} FAILED: ${r.error || 'unknown error'}`
      );
      setFreeLog([
        `Detected target type: ${bundle.queryType}`,
        ...(bundle.results.length === 0
          ? [
              'No free provider matches this target type. Free recon covers domains, IPs, emails, and URLs. For usernames use the keyed Sherlock scan; for people add Hunter/HIBP keys.',
            ]
          : providerLines),
        ...(bundle.results.length > 0
          ? ['Merged into case — open Entities / Evidence tabs.']
          : []),
      ]);
    } catch (err) {
      setFreeLog([err instanceof Error ? err.message : 'Free recon failed']);
    } finally {
      setFreeBusy(false);
    }
  }

  async function runSpiderfoot() {
    const target = sfTarget.trim();
    if (!target) {
      setSfLog(['Enter a target (domain, IP, or email)']);
      return;
    }
    const base = ensureCase();
    setSfBusy(true);
    setSfLog([`SpiderFoot scan on ${target}…`]);
    try {
      const result = await lookupSpiderfoot(target);
      updateCase(mergeProviderIntoCase(base, [result]));
      setSfLog(
        [
          result.ok
            ? `${result.provider}: ${result.rawSummary || `${result.hits.length} hit(s)`}`
            : `${result.provider}: ${result.error || 'failed'}`,
          result.mode ? `Mode: ${result.mode}` : '',
          typeof result.eventCount === 'number' ? `Events: ${result.eventCount}` : '',
          'Merged into case — open Entities / Evidence tabs.',
        ].filter(Boolean)
      );
    } catch (err) {
      setSfLog([err instanceof Error ? err.message : 'SpiderFoot failed']);
    } finally {
      setSfBusy(false);
    }
  }

  async function runEmailLookup() {
    const email = lookupEmail.trim();
    if (!email) {
      setLookupLog(['Enter an email']);
      return;
    }
    const base = ensureCase();
    setLookupBusy(true);
    setLookupLog([`Looking up ${email} (HIBP + Hunter)…`]);
    try {
      const bundle = await lookupEmailBundle(email);
      setLastProviders(bundle.results);
      updateCase(mergeProviderIntoCase(base, bundle.results));
      setLookupLog([
        ...bundle.results.map((r) =>
          r.ok
            ? `${r.provider}: ${r.rawSummary || `${r.hits.length} hit(s)`} · entities=${r.entities.length} evidence=${r.evidence.length}`
            : `${r.provider} FAILED: ${r.error || 'unknown error'}`
        ),
        'Merged into case — open Entities / Evidence or scroll for hit list.',
      ]);
      setActiveTab('lookup');
    } catch (err) {
      setLookupLog([err instanceof Error ? err.message : 'Email lookup failed']);
    } finally {
      setLookupBusy(false);
    }
  }

  async function runDomainLookup() {
    const domain = lookupDomain.trim();
    if (!domain) {
      setLookupLog(['Enter a domain']);
      return;
    }
    const base = ensureCase();
    setLookupBusy(true);
    setLookupLog([`Looking up domain ${domain}…`]);
    try {
      const results = await Promise.all([
        lookupHunterDomain(domain),
        lookupVirusTotalDomain(domain),
      ]);
      setLastProviders(results);
      updateCase(mergeProviderIntoCase(base, results));
      setLookupLog(
        results.map((r) =>
          r.ok
            ? `${r.provider}: ${r.rawSummary || `${r.hits.length} hit(s)`}`
            : `${r.provider}: ${r.error || 'failed'}`
        )
      );
      setActiveTab('evidence');
    } catch (err) {
      setLookupLog([err instanceof Error ? err.message : 'Domain lookup failed']);
    } finally {
      setLookupBusy(false);
    }
  }

  async function runIpLookup() {
    const ip = lookupIp.trim();
    if (!ip) {
      setLookupLog(['Enter an IP']);
      return;
    }
    const base = ensureCase();
    setLookupBusy(true);
    setLookupLog([`Looking up IP ${ip}…`]);
    try {
      const results = await Promise.all([lookupShodan(ip), lookupAbuseIp(ip)]);
      setLastProviders(results);
      updateCase(mergeProviderIntoCase(base, results));
      setLookupLog(
        results.map((r) =>
          r.ok
            ? `${r.provider}: ${r.rawSummary || `${r.hits.length} hit(s)`}`
            : `${r.provider}: ${r.error || 'failed'}`
        )
      );
      setActiveTab('evidence');
    } catch (err) {
      setLookupLog([err instanceof Error ? err.message : 'IP lookup failed']);
    } finally {
      setLookupBusy(false);
    }
  }

  async function runPhoneLookup() {
    const phone = lookupPhone.trim();
    if (!phone) {
      setLookupLog(['Enter a phone number']);
      return;
    }
    const base = ensureCase();
    setLookupBusy(true);
    setLookupLog([`Looking up phone ${phone}…`]);
    try {
      const result = await lookupNumverify(phone);
      setLastProviders([result]);
      updateCase(mergeProviderIntoCase(base, [result]));
      setLookupLog([
        result.ok
          ? `${result.provider}: ${result.rawSummary || `${result.hits.length} hit(s)`}`
          : `${result.provider}: ${result.error || 'failed'}`,
      ]);
      setActiveTab('evidence');
    } catch (err) {
      setLookupLog([err instanceof Error ? err.message : 'Phone lookup failed']);
    } finally {
      setLookupBusy(false);
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">OSINT Workbench Platform</div>
          <h1>Live lookups only — no sample profiles</h1>
          <p>
            Free no-key recon works out of the box (DNS, RDAP WHOIS, CT logs, host search, IP
            geo, Shodan InternetDB, IP RDAP, Gravatar, Wayback). Paid providers (HIBP, Hunter,
            Shodan, VirusTotal, AbuseIPDB, Numverify) activate when their keys are set. Nothing is
            invented — every finding stays POSSIBLE until you verify it.
          </p>
          {health && (
            <div className="provider-status">
              <span className="chip chip-ok">v{health.version}</span>
              <span className="chip chip-free">
                {health.freeProviders?.length ?? 0} free providers
              </span>
              <span className="chip chip-ok">
                {(health.providersConfigured?.length ?? 0)} keyed
              </span>
              <span className="chip chip-muted">
                {(health.providersMissing?.length ?? 0)} missing keys
              </span>
            </div>
          )}
        </div>
        <div className="stats">
          <div>
            <span>Cases</span>
            <strong>{stats.cases}</strong>
          </div>
          <div>
            <span>Correlation hits</span>
            <strong>{stats.correlations}</strong>
          </div>
          <div>
            <span>Attachments</span>
            <strong>{stats.attachments}</strong>
          </div>
          <div>
            <span>Verified findings</span>
            <strong>{stats.verified}</strong>
          </div>
        </div>
      </header>

      {storageWarning && (
        <div className="banner banner-warn" role="alert">
          <strong>Local storage is full.</strong> Your latest changes could not be saved to this
          browser. Export your cases as JSON or a bundle to avoid losing work.
        </div>
      )}

      <nav className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab}
            className={activeTab === tab ? 'active' : ''}
            onClick={() => setActiveTab(tab)}
          >
            {tab}
          </button>
        ))}
      </nav>

      <main className="grid">
        {activeTab === 'cases' && (
          <section className="panel full">
            <h2>Cases</h2>
            <div className="actions-row" style={{ marginBottom: '0.75rem' }}>
              <button className="action" onClick={newCase}>
                New empty case
              </button>
              <button className="action ghost" onClick={() => importInputRef.current?.click()}>
                Import case JSON
              </button>
              <input
                ref={importInputRef}
                type="file"
                accept=".json,application/json"
                style={{ display: 'none' }}
                onChange={(e) => void handleImportFile(e.target.files?.[0])}
              />
            </div>
            {importError && (
              <div className="line-item" role="alert" style={{ color: '#f87171' }}>
                Import failed: {importError}
              </div>
            )}
            {cases.length === 0 && (
              <div className="line-item muted">
                No cases yet. Create one, then use Lookup for live API results only.
              </div>
            )}
            <div className="cards">
              {cases.map((record) => (
                <article
                  key={record.id}
                  className={`card${record.id === activeCaseId ? ' selected' : ''}`}
                >
                  <button
                    className="card-head"
                    onClick={() => {
                      setActiveCaseId(record.id);
                      setActiveTab('lookup');
                    }}
                  >
                    <strong>{record.name}</strong>
                    <span>{record.type}</span>
                    <small>
                      {record.entities.length} entities · {record.evidence.length} evidence ·{' '}
                      {record.entities.filter((e) => e.verified).length +
                        record.evidence.filter((e) => e.verified).length}{' '}
                      verified
                    </small>
                  </button>
                  <div className="actions-row">
                    <button
                      className="action ghost small"
                      onClick={() => {
                        setActiveCaseId(record.id);
                        setActiveTab('lookup');
                      }}
                    >
                      Open
                    </button>
                    <button
                      className="action danger small"
                      onClick={() => handleDeleteCase(record.id)}
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>

            {activeCase && (
              <article className="line-item" style={{ marginTop: '1rem' }}>
                <strong>Case settings — {activeCase.name}</strong>
                <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                  <input
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    placeholder="Rename case"
                    style={inputStyle}
                  />
                  <button className="action" onClick={handleRenameCase}>
                    Save name
                  </button>
                </div>
              </article>
            )}
          </section>
        )}

        {activeTab === 'lookup' && (
          <section className="panel full">
            <h2>Live lookup</h2>
            <p className="muted">
              Free recon needs no keys. Paid providers require server environment keys — missing
              keys return an explicit error, never fake data.
            </p>

            <article className="line-item highlight">
              <strong>Free recon (no API key) — auto-detect</strong>
              <p className="muted">
                Enter a domain, IP, email, or URL. Runs DNS (DoH), RDAP WHOIS, certificate
                transparency, host search, IP geolocation, Gravatar, and the Wayback Machine as
                applicable.
              </p>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={freeTarget}
                  onChange={(e) => setFreeTarget(e.target.value)}
                  placeholder="example.com · 1.2.3.4 · name@example.com"
                  style={inputStyle}
                  disabled={freeBusy}
                />
                <button className="action" onClick={runFreeLookup} disabled={freeBusy}>
                  {freeBusy ? 'Running…' : 'Run free recon'}
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>Email (HIBP + Hunter)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={lookupEmail}
                  onChange={(e) => setLookupEmail(e.target.value)}
                  placeholder="name@example.com"
                  style={inputStyle}
                  disabled={lookupBusy}
                />
                <button className="action" onClick={runEmailLookup} disabled={lookupBusy}>
                  Lookup email
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>Username (Sherlock)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={sherlockInput}
                  onChange={(e) => setSherlockInput(e.target.value)}
                  placeholder="username"
                  style={inputStyle}
                  disabled={sherlockBusy}
                />
                <button className="action" onClick={handleSherlockScan} disabled={sherlockBusy}>
                  {sherlockBusy ? 'Scanning…' : 'Run Sherlock'}
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>Domain (Hunter + VirusTotal)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={lookupDomain}
                  onChange={(e) => setLookupDomain(e.target.value)}
                  placeholder="example.com"
                  style={inputStyle}
                  disabled={lookupBusy}
                />
                <button className="action" onClick={runDomainLookup} disabled={lookupBusy}>
                  Lookup domain
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>IP (Shodan + AbuseIPDB)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={lookupIp}
                  onChange={(e) => setLookupIp(e.target.value)}
                  placeholder="1.2.3.4"
                  style={inputStyle}
                  disabled={lookupBusy}
                />
                <button className="action" onClick={runIpLookup} disabled={lookupBusy}>
                  Lookup IP
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>Phone (Numverify)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={lookupPhone}
                  onChange={(e) => setLookupPhone(e.target.value)}
                  placeholder="+61412345678"
                  style={inputStyle}
                  disabled={lookupBusy}
                />
                <button className="action" onClick={runPhoneLookup} disabled={lookupBusy}>
                  Lookup phone
                </button>
              </div>
            </article>

            <article className="line-item">
              <strong>SpiderFoot (host CLI — optional)</strong>
              <p className="muted">
                Deep scan via a SpiderFoot CLI on the host (SPIDERFOOT_BIN). Not available on
                typical free hosting.
              </p>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={sfTarget}
                  onChange={(e) => setSfTarget(e.target.value)}
                  placeholder="example.com"
                  style={inputStyle}
                  disabled={sfBusy}
                />
                <button className="action" onClick={runSpiderfoot} disabled={sfBusy}>
                  {sfBusy ? 'Scanning…' : 'Run SpiderFoot'}
                </button>
              </div>
            </article>

            {freeLog.length > 0 && (
              <div className="log">
                <strong>Free recon</strong>
                {freeLog.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            )}

            {sfLog.length > 0 && (
              <div className="log">
                <strong>SpiderFoot</strong>
                {sfLog.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            )}

            {(lookupLog.length > 0 || sherlockLog.length > 0) && (
              <div className="log">
                <strong>Keyed providers</strong>
                {[...lookupLog, ...sherlockLog].map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            )}

            {lastFree && (
              <article className="line-item">
                <strong>
                  free recon — {lastFree.query} ({lastFree.queryType})
                </strong>
                {lastFree.results.map((r) => (
                  <div key={r.provider} style={{ marginTop: '0.4rem' }}>
                    <em>{r.provider}</em>
                    {!r.ok && <div className="muted">{r.error}</div>}
                    {r.ok && r.rawSummary ? <div className="muted">{r.rawSummary}</div> : null}
                    <ul className="match-list">
                      {r.hits.slice(0, 25).map((h: HitLike, i: number) => (
                        <li key={i}>
                          {typeof h === 'string' ? (
                            h
                          ) : h?.url ? (
                            <a href={h.url} target="_blank" rel="noreferrer">
                              {h.title || h.url}
                            </a>
                          ) : (
                            (h && h.title) || String(h)
                          )}
                          {typeof h === 'object' && h?.detail ? ` — ${h.detail}` : ''}
                        </li>
                      ))}
                      {r.ok && r.hits.length === 0 && <li className="muted">No hits</li>}
                    </ul>
                  </div>
                ))}
              </article>
            )}

            {lastProviders.map((r) => (
              <div key={r.provider + r.query} className="line-item">
                <strong>
                  {r.provider} — {r.query}
                </strong>
                {!r.ok && <div className="muted">{r.error}</div>}
                {r.ok && r.rawSummary ? <div className="muted">{r.rawSummary}</div> : null}
                <ul className="match-list">
                  {r.hits.map((h: HitLike, i: number) => (
                    <li key={i}>
                      {typeof h === 'string' ? (
                        h
                      ) : h?.url ? (
                        <a href={h.url} target="_blank" rel="noreferrer">
                          {h.title || h.url}
                        </a>
                      ) : (
                        (h && h.title) || String(h)
                      )}
                      {typeof h === 'object' && h?.detail ? ` — ${h.detail}` : ''}
                    </li>
                  ))}
                  {r.ok && r.hits.length === 0 && <li className="muted">No hits</li>}
                </ul>
              </div>
            ))}

            {lastSherlock &&
              lastSherlock.map((result) => (
                <div key={result.username} className="line-item">
                  <strong>sherlock — {result.username}</strong> <em>({result.mode})</em>
                  <ul className="match-list">
                    {result.hits
                      .filter((h) => h.status === 'found')
                      .map((h) => (
                        <li key={h.site}>
                          <a href={h.url} target="_blank" rel="noreferrer">
                            {h.site}
                          </a>
                        </li>
                      ))}
                    {result.hits.filter((h) => h.status === 'found').length === 0 && (
                      <li className="muted">No profiles found</li>
                    )}
                  </ul>
                </div>
              ))}
          </section>
        )}

        {activeCase && activeTab === 'entities' && (
          <section className="panel full">
            <h2>Entities — {activeCase.name}</h2>
            <p className="muted">
              Tools never verify. Promote confidence one step, or mark a finding verified as the
              analyst. Verified findings are pinned to High.
            </p>
            {activeCase.entities.length === 0 && (
              <div className="line-item muted">No entities yet. Run a live lookup.</div>
            )}
            <div className="cards">
              {activeCase.entities.map((entity) => (
                <article
                  key={entity.id}
                  className={`card${entity.verified ? ' verified' : ''}`}
                >
                  <div className="card-head static">
                    <strong>{entity.name}</strong>
                    <span>
                      {entity.type} · <ConfidenceBadge value={entity.confidence} verified={entity.verified} />
                    </span>
                  </div>
                  <small>{entity.identifiers.join(' · ')}</small>
                  {entity.notes && <p className="muted">{entity.notes}</p>}
                  {entity.verified && entity.verifiedBy && (
                    <small className="muted">
                      Verified by {entity.verifiedBy}
                      {entity.verifiedAt ? ` · ${new Date(entity.verifiedAt).toLocaleString()}` : ''}
                    </small>
                  )}
                  <div className="actions-row">
                    <button
                      className="action ghost small"
                      onClick={() => updateCase(promoteEntityConfidence(activeCase, entity.id))}
                    >
                      Promote ▲
                    </button>
                    <button
                      className="action small"
                      onClick={() => updateCase(verifyEntity(activeCase, entity.id))}
                    >
                      Verify ✓
                    </button>
                    {entity.verified && (
                      <button
                        className="action ghost small"
                        onClick={() => updateCase(unverifyEntity(activeCase, entity.id))}
                      >
                        Unverify
                      </button>
                    )}
                    <button
                      className="action danger small"
                      onClick={() => updateCase(removeEntity(activeCase, entity.id))}
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {activeCase && activeTab === 'evidence' && (
          <section className="panel full">
            <h2>Evidence — {activeCase.name}</h2>
            {activeCase.evidence.length === 0 && (
              <div className="line-item muted">No evidence yet. Run a live lookup.</div>
            )}
            <div className="cards">
              {activeCase.evidence.map((evidence) => (
                <article
                  key={evidence.id}
                  className={`card${evidence.verified ? ' verified' : ''}`}
                >
                  <div className="card-head static">
                    <strong>{evidence.title}</strong>
                    <ConfidenceBadge value={evidence.confidence} verified={evidence.verified} />
                  </div>
                  {evidence.url && (
                    <a href={evidence.url} target="_blank" rel="noreferrer">
                      {evidence.url}
                    </a>
                  )}
                  <p className="muted">{evidence.notes}</p>
                  <small>{evidence.tags.join(', ')}</small>
                  <div className="actions-row">
                    <button
                      className="action ghost small"
                      onClick={() =>
                        updateCase(promoteEvidenceConfidence(activeCase, evidence.id))
                      }
                    >
                      Promote ▲
                    </button>
                    <button
                      className="action small"
                      onClick={() => updateCase(verifyEvidence(activeCase, evidence.id))}
                    >
                      Verify ✓
                    </button>
                    {evidence.verified && (
                      <button
                        className="action ghost small"
                        onClick={() => updateCase(unverifyEvidence(activeCase, evidence.id))}
                      >
                        Unverify
                      </button>
                    )}
                    <button
                      className="action danger small"
                      onClick={() => updateCase(removeEvidence(activeCase, evidence.id))}
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {activeCase && activeTab === 'analysis' && (
          <section className="panel full two-col">
            <article>
              <h2>Timeline</h2>
              {activeCase.events.length === 0 && <div className="line-item muted">No events</div>}
              {activeCase.events.map((event: TimelineEvent) => (
                <div key={event.id} className="line-item">
                  {event.date} — {event.title}
                </div>
              ))}
            </article>
            <article>
              <h2>Provenance</h2>
              {activeCase.provenance.length === 0 && (
                <div className="line-item muted">No provenance</div>
              )}
              {activeCase.provenance.map((step: ProvenanceStep) => (
                <div key={step.id} className="line-item">
                  {step.claim}
                </div>
              ))}
            </article>
          </section>
        )}

        {activeCase && activeTab === 'graph' && (
          <section className="panel full">
            <div className="two-col">
              <article>
                <h2>Relationships</h2>
                {activeCase.relationships.length === 0 && (
                  <div className="line-item muted">No relationships</div>
                )}
                {activeCase.relationships.map((rel) => {
                  const source =
                    activeCase.entities.find((e) => e.id === rel.sourceId)?.name ?? 'Unknown';
                  const target =
                    activeCase.entities.find((e) => e.id === rel.targetId)?.name ?? 'Unknown';
                  return (
                    <div key={rel.id} className="line-item rel-row">
                      <span>
                        {source} → {target} · {rel.type}{' '}
                        <ConfidenceBadge value={rel.confidence} />
                      </span>
                      <button
                        className="action danger small"
                        onClick={() => updateCase(removeRelationship(activeCase, rel.id))}
                      >
                        Remove
                      </button>
                    </div>
                  );
                })}

                <article className="line-item" style={{ marginTop: '1rem' }}>
                  <strong>Link two entities</strong>
                  <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                    <select
                      value={relSource}
                      onChange={(e) => setRelSource(e.target.value)}
                      style={inputStyle}
                    >
                      <option value="">source…</option>
                      {activeCase.entities.map((e) => (
                        <option key={e.id} value={e.id}>
                          {e.name}
                        </option>
                      ))}
                    </select>
                    <select
                      value={relTarget}
                      onChange={(e) => setRelTarget(e.target.value)}
                      style={inputStyle}
                    >
                      <option value="">target…</option>
                      {activeCase.entities.map((e) => (
                        <option key={e.id} value={e.id}>
                          {e.name}
                        </option>
                      ))}
                    </select>
                    <input
                      value={relType}
                      onChange={(e) => setRelType(e.target.value)}
                      placeholder="relationship (e.g. owns, alias-of)"
                      style={inputStyle}
                    />
                    <button
                      className="action"
                      onClick={() => {
                        updateCase(addRelationship(activeCase, relSource, relTarget, relType));
                        setRelType('');
                      }}
                    >
                      Add link
                    </button>
                  </div>
                </article>
              </article>
              <article>
                <h2>Cross-case correlation</h2>
                <button
                  onClick={() => setCorrelationHits(buildCorrelationHits(cases))}
                  className="action"
                >
                  Re-run correlation
                </button>
                {correlationHits.length === 0 && (
                  <div className="line-item muted">No cross-case tokens</div>
                )}
                {correlationHits.map((hit) => (
                  <div key={hit.token} className="line-item">
                    <strong>{hit.token}</strong>
                    <br />
                    {hit.matches.length} matches across{' '}
                    {new Set(hit.matches.map((m) => m.caseId)).size} cases
                  </div>
                ))}
              </article>
            </div>
          </section>
        )}

        {activeTab === 'framework' && (
          <section className="panel full">
            <h2>OSINT Framework</h2>
            <p className="muted">
              Optional external tool links. Prefer the Lookup tab for live API data into this case.
            </p>
            <div className="actions-row" style={{ marginBottom: '0.75rem' }}>
              <button className="action" onClick={() => void loadFramework()} disabled={frameworkLoading}>
                {frameworkLoading ? 'Loading…' : framework ? 'Refresh' : 'Load catalog'}
              </button>
            </div>
            {frameworkError && <div className="line-item">{frameworkError}</div>}
            {framework && (
              <>
                <input
                  value={frameworkQuery}
                  onChange={(e) => setFrameworkQuery(e.target.value)}
                  placeholder="Optional query for external tools"
                  style={{ ...inputStyle, borderRadius: 12, width: '100%', margin: '0.75rem 0' }}
                />
                {framework.categories.map((cat) => (
                  <article key={cat.id} style={{ marginBottom: '1rem' }}>
                    <h3>
                      {cat.name}
                      {cat.id === 'free' && <span className="chip chip-free">no key</span>}
                    </h3>
                    <div className="cards">
                      {cat.tools.map((tool) => (
                        <div key={tool.id} className="card">
                          <strong>{tool.name}</strong>
                          <p className="muted">{tool.description}</p>
                          <button
                            className="action"
                            onClick={() => launchFrameworkTool(tool, frameworkQuery)}
                          >
                            Open external
                          </button>
                        </div>
                      ))}
                    </div>
                  </article>
                ))}
              </>
            )}
          </section>
        )}

        {activeCase && activeTab === 'report' && (
          <section className="panel full actions">
            <h2>Exports — {activeCase.name}</h2>
            <p className="muted">
              {activeCase.report.summary}
              <br />
              {activeCase.report.next}
            </p>
            <div className="actions-row">
              <button
                className="action"
                onClick={() => downloadJson(activeCase, sanitizeFilename(activeCase.name) + '.json')}
              >
                Case JSON
              </button>
              <button
                className="action"
                onClick={() => exportHtmlReport(activeCase, correlationHits)}
              >
                HTML report
              </button>
              <button
                className="action"
                onClick={() => exportGraphML(activeCase, correlationHits)}
              >
                GraphML
              </button>
              <button
                className="action"
                onClick={() => exportBundleZip(activeCase, correlationHits)}
              >
                ZIP bundle
              </button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
