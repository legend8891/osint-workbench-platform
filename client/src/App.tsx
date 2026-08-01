import { useMemo, useState } from 'react';
import type {
  CaseRecord,
  CorrelationHit,
  TimelineEvent,
  ProvenanceStep,
} from 'shared';
import { sampleCases } from '../store/sampleData';
import {
  buildCorrelationHits,
  downloadJson,
  exportBundleZip,
  exportHtmlReport,
  exportGraphML,
  runSherlockScan,
  mergeScanIntoCase,
  type SherlockScanResult,
} from '../lib/workbench';

const tabs = ['cases', 'entities', 'evidence', 'analysis', 'graph', 'report'] as const;
type Tab = (typeof tabs)[number];

export function App() {
  const [activeTab, setActiveTab] = useState<Tab>('cases');
  const [cases, setCases] = useState<CaseRecord[]>(sampleCases);
  const [activeCaseId, setActiveCaseId] = useState<string>(sampleCases[0]?.id ?? '');
  const [correlationHits, setCorrelationHits] = useState<CorrelationHit[]>(() =>
    buildCorrelationHits(sampleCases)
  );
  const [sherlockInput, setSherlockInput] = useState('alexmorgan');
  const [sherlockBusy, setSherlockBusy] = useState(false);
  const [sherlockLog, setSherlockLog] = useState<string[]>([]);
  const [lastSherlock, setLastSherlock] = useState<SherlockScanResult[] | null>(null);

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

  function rerunCorrelations(nextCases = cases) {
    setCorrelationHits(buildCorrelationHits(nextCases));
  }

  function updateCase(next: CaseRecord) {
    setCases((prev) => {
      const updated = prev.map((c) => (c.id === next.id ? next : c));
      setCorrelationHits(buildCorrelationHits(updated));
      return updated;
    });
  }

  async function handleSherlockScan() {
    if (!activeCase || sherlockBusy) return;
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
      const merged = mergeScanIntoCase(activeCase, api.results);
      updateCase(merged);
      const lines = [
        `Mode: ${api.summary.mode}`,
        `Found: ${api.summary.totalFound} profile(s) across ${api.summary.usernames} username(s)`,
        ...api.results.flatMap((r) => r.notes),
      ];
      setSherlockLog(lines);
    } catch (err) {
      setSherlockLog([
        err instanceof Error ? err.message : 'Scan failed',
        'Is the API running on :8787? (npm run dev)',
      ]);
    } finally {
      setSherlockBusy(false);
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">OSINT Workbench Platform</div>
          <h1>iOS-first graph and correlation workspace</h1>
          <p>
            React/Vite frontend with shared Zod contracts, cross-case token correlation,
            provenance, and evidence-package export.
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
            <span>Attachments</span>
            <strong>{stats.attachments}</strong>
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
            <div className="cards">
              {cases.map((record) => (
                <button
                  key={record.id}
                  className="card selectable"
                  onClick={() => {
                    setActiveCaseId(record.id);
                    setActiveTab('entities');
                  }}
                >
                  <strong>{record.name}</strong>
                  <span>{record.type}</span>
                  <span>{record.location}</span>
                  <small>
                    {record.entities.length} entities · {record.evidence.length} evidence
                  </small>
                </button>
              ))}
            </div>
          </section>
        )}

        {activeCase && activeTab === 'entities' && (
          <section className="panel full">
            <h2>Entities — {activeCase.name}</h2>
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
            <div className="cards">
              {activeCase.evidence.map((evidence) => (
                <article key={evidence.id} className="card">
                  <strong>{evidence.title}</strong>
                  <a href={evidence.url} target="_blank" rel="noreferrer">
                    {evidence.url}
                  </a>
                  {evidence.archiveUrl && (
                    <a
                      href={evidence.archiveUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="archive"
                    >
                      Archive / cached
                    </a>
                  )}
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
                <div className="line-item muted">No timeline events</div>
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
                <div className="line-item muted">No provenance steps</div>
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
                  <div className="line-item muted">No relationships recorded</div>
                )}
                {activeCase.relationships.map((rel) => {
                  const source =
                    activeCase.entities.find((e) => e.id === rel.sourceId)?.name ??
                    'Unknown';
                  const target =
                    activeCase.entities.find((e) => e.id === rel.targetId)?.name ??
                    'Unknown';
                  return (
                    <div key={rel.id} className="line-item">
                      {source} → {target} · {rel.type} ({rel.confidence})
                    </div>
                  );
                })}
              </article>
              <article>
                <h2>Cross-case correlation</h2>
                <button onClick={() => rerunCorrelations()} className="action">
                  Re-run correlation
                </button>
                {correlationHits.length === 0 && (
                  <div className="line-item muted">No cross-case tokens found</div>
                )}
                {correlationHits.map((hit) => (
                  <div key={hit.token} className="line-item">
                    <strong>{hit.token}</strong>
                    <br />
                    {hit.matches.length} matches across{' '}
                    {new Set(hit.matches.map((m) => m.caseId)).size} cases
                    <ul className="match-list">
                      {hit.matches.map((m, i) => (
                        <li key={`${m.caseId}-${m.entityId}-${i}`}>
                          {m.caseName} / {m.entityName} ({m.entityType})
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </article>
            </div>

            <article className="sherlock-panel">
              <h2>Username enumeration (Sherlock)</h2>
              <p className="muted">
                Server-side scan. Uses Sherlock CLI if installed; otherwise a limited Node
                fallback. All hits are labelled <strong>POSSIBLE</strong> — never auto-verified.
              </p>
              <div className="actions-row" style={{ marginBottom: '0.75rem' }}>
                <input
                  type="text"
                  value={sherlockInput}
                  onChange={(e) => setSherlockInput(e.target.value)}
                  placeholder="username1, username2"
                  aria-label="Usernames to scan"
                  style={{
                    flex: 1,
                    minHeight: 44,
                    padding: '0.75rem 1rem',
                    borderRadius: 999,
                    border: '1px solid rgba(0,0,0,.15)',
                    minWidth: 180,
                  }}
                  disabled={sherlockBusy}
                />
                <button
                  className="action"
                  onClick={handleSherlockScan}
                  disabled={sherlockBusy}
                >
                  {sherlockBusy ? 'Scanning…' : 'Run Sherlock'}
                </button>
              </div>
              {sherlockLog.length > 0 && (
                <div className="line-item">
                  {sherlockLog.map((line, i) => (
                    <div key={i}>{line}</div>
                  ))}
                </div>
              )}
              {lastSherlock &&
                lastSherlock.map((result) => (
                  <div key={result.username} className="line-item">
                    <strong>
                      {result.username}
                    </strong>{' '}
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
            </article>
          </section>
        )}

        {activeCase && activeTab === 'report' && (
          <section className="panel full actions">
            <h2>Exports — {activeCase.name}</h2>
            <p className="muted">
              Summary: {activeCase.report.summary}
              <br />
              Next: {activeCase.report.next}
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
            <p className="muted" style={{ marginTop: '0.75rem' }}>
              GraphML includes entities, relationships, evidence links, and correlation tokens
              (all labelled POSSIBLE). Import into Maltego, Gephi, or yEd for link analysis.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
