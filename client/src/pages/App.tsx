import { useMemo, useState } from 'react';
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
  mergeProviderIntoCase,
  type SherlockScanResult,
  type FrameworkCatalog,
  type ProviderLookupResult,
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

export function App() {
  const [activeTab, setActiveTab] = useState<Tab>('cases');
  const [cases, setCases] = useState<CaseRecord[]>(sampleCases);
  const [activeCaseId, setActiveCaseId] = useState<string>('');
  const [correlationHits, setCorrelationHits] = useState<CorrelationHit[]>([]);
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

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) ?? null,
    [cases, activeCaseId]
  );

  const stats = useMemo(() => {
    const attachments = cases.reduce(
      (count, c) => count + c.evidence.reduce((n, e) => n + e.attachments.length, 0),
      0
    );
    return { cases: cases.length, correlations: correlationHits.length, attachments };
  }, [cases, correlationHits]);

  function ensureCase(): CaseRecord {
    if (activeCase) return activeCase;
    return createEmptyCase();
  }

  function updateCase(next: CaseRecord) {
    setCases((prev) => {
      const exists = prev.some((c) => c.id === next.id);
      const updated = exists
        ? prev.map((c) => (c.id === next.id ? next : c))
        : [...prev, next];
      setCorrelationHits(buildCorrelationHits(updated));
      return updated;
    });
    setActiveCaseId(next.id);
  }

  function newCase() {
    const created = createEmptyCase(`Investigation ${cases.length + 1}`);
    setCases((prev) => [...prev, created]);
    setActiveCaseId(created.id);
    setActiveTab('lookup');
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
            Results come from configured APIs (HIBP, Hunter, Shodan, VirusTotal, AbuseIPDB,
            Numverify, Sherlock). Nothing is invented. All findings stay POSSIBLE until you
            verify them.
          </p>
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
            <span>Evidence items</span>
            <strong>
              {cases.reduce((n, c) => n + c.evidence.length, 0)}
            </strong>
          </div>
        </div>
      </header>

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
            </div>
            {cases.length === 0 && (
              <div className="line-item muted">
                No cases yet. Create one, then use Lookup for live API results only.
              </div>
            )}
            <div className="cards">
              {cases.map((record) => (
                <button
                  key={record.id}
                  className="card selectable"
                  onClick={() => {
                    setActiveCaseId(record.id);
                    setActiveTab('lookup');
                  }}
                >
                  <strong>{record.name}</strong>
                  <span>{record.type}</span>
                  <small>
                    {record.entities.length} entities · {record.evidence.length} evidence
                  </small>
                </button>
              ))}
            </div>
          </section>
        )}

        {activeTab === 'lookup' && (
          <section className="panel full">
            <h2>Live lookup</h2>
            <p className="muted">
              Requires API keys on the server (Render Environment). Missing keys return an
              explicit error — never fake data.
            </p>

            <article className="line-item">
              <strong>Email (HIBP + Hunter)</strong>
              <div className="actions-row" style={{ marginTop: '0.5rem' }}>
                <input
                  value={lookupEmail}
                  onChange={(e) => setLookupEmail(e.target.value)}
                  placeholder="name@example.com"
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
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
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
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
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
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
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
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
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
                  disabled={lookupBusy}
                />
                <button className="action" onClick={runPhoneLookup} disabled={lookupBusy}>
                  Lookup phone
                </button>
              </div>
            </article>

            {(lookupLog.length > 0 || sherlockLog.length > 0) && (
              <div className="line-item">
                {[...lookupLog, ...sherlockLog].map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            )}

            {lastProviders.map((r) => (
              <div key={r.provider + r.query} className="line-item">
                <strong>
                  {r.provider} — {r.query}
                </strong>
                {!r.ok && <div className="muted">{r.error}</div>}
                {r.ok && r.rawSummary ? <div className="muted">{r.rawSummary}</div> : null}
                <ul className="match-list">
                  {r.hits.map((h: any, i: number) => (
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
                  <strong>sherlock — {result.username}</strong>{' '}
                  <em>({result.mode})</em>
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
            {activeCase.entities.length === 0 && (
              <div className="line-item muted">No entities yet. Run a live lookup.</div>
            )}
            <div className="cards">
              {activeCase.entities.map((entity) => (
                <article key={entity.id} className="card">
                  <strong>{entity.name}</strong>
                  <span>
                    {entity.type} · <em>{entity.confidence}</em>
                  </span>
                  <small>{entity.identifiers.join(' · ')}</small>
                  {entity.notes && <p className="muted">{entity.notes}</p>}
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
                <article key={evidence.id} className="card">
                  <strong>{evidence.title}</strong>
                  {evidence.url && (
                    <a href={evidence.url} target="_blank" rel="noreferrer">
                      {evidence.url}
                    </a>
                  )}
                  <p className="muted">{evidence.notes}</p>
                  <small>
                    {evidence.tags.join(', ')} · {evidence.confidence}
                  </small>
                </article>
              ))}
            </div>
          </section>
        )}

        {activeCase && activeTab === 'analysis' && (
          <section className="panel full two-col">
            <article>
              <h2>Timeline</h2>
              {activeCase.events.length === 0 && (
                <div className="line-item muted">No events</div>
              )}
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
                    <div key={rel.id} className="line-item">
                      {source} → {target} · {rel.type} ({rel.confidence})
                    </div>
                  );
                })}
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
              Optional external tool links. Prefer the Lookup tab for live API data into this
              case.
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
                  style={{
                    width: '100%',
                    minHeight: 44,
                    margin: '0.75rem 0',
                    padding: '0.75rem 1rem',
                    borderRadius: 12,
                    border: '1px solid rgba(0,0,0,.15)',
                  }}
                />
                {framework.categories.map((cat) => (
                  <article key={cat.id} style={{ marginBottom: '1rem' }}>
                    <h3>{cat.name}</h3>
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
                onClick={() => downloadJson(activeCase, `${activeCase.name}.json`)}
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
