# OSINT Workbench Platform — Code Review & Improvement Plan

**Reviewed:** v0.11.0 · `main` @ `f7639ca`
**Scope:** full monorepo (~5,080 LOC of TS/TSX/CSS) — `server`, `client`, `shared`, plus config/deploy files.
**Method:** static read of every source file, dependency/version audit, and a clean production build (`npm run build` → exit 0, 45 modules, 327 kB JS / 97 kB gzip).

---

## 1. Executive summary

This is a genuinely well-built, honest OSINT tool. The standout design decision — **tools never auto-verify; a human must promote every finding** — is exactly right for the domain and is implemented consistently across the confidence ladder (`Unverified → Low → Medium → High`), the `verified/verifiedAt/verifiedBy` fields, and the provenance log. The free, keyless provider set (DNS-over-HTTPS, RDAP, crt.sh, HackerTarget, ipwho.is, Gravatar, Wayback) means the app is useful the instant it deploys, and the server correctly refuses to fabricate data when a key is missing.

The main weaknesses are **polish and robustness, not architecture**: a broken PWA icon reference, export/report functions that drop data the case already holds, silent data-loss paths in persistence, a 1,100-line `App.tsx` monolith, no tests, and a few production-hardening gaps (open CORS, source maps shipped, no security headers).

**Scorecard**

| Area | Grade | Notes |
|---|---|---|
| Domain design (verification model) | A | Best-in-class for the problem |
| Server / providers | B+ | Clean, honest, throttled; a few hardening gaps |
| Client UX | B− | Works end-to-end; monolithic, some a11y gaps |
| Data model | B | Solid schemas; no import path, no dedupe |
| Security / ops | C+ | Open CORS, sourcemaps, no helmet, XFF trust |
| Testing | F | Zero tests |
| Docs | A− | README/BUILD_SUMMARY/DEPLOY are strong |

---

## 2. What's already strong (keep doing this)

- **No fabricated data.** `providers.ts` and `freerecon.ts` only ever map real upstream responses; missing keys return an explicit error (`emptyResult`), never a placeholder profile. This is the single most important property of an OSINT tool and it's upheld everywhere.
- **Analyst-in-the-loop verification.** `verifyEntity`/`verifyEvidence` pin confidence to `High` and stamp `verifiedBy`/`verifiedAt`; `promoteConfidence` moves one rung and explicitly resets `verified: false`. Tools never call these.
- **Provenance trail.** Every provider hit writes an `Entity + Evidence + Provenance` triple, so claims are traceable to a source URL.
- **Outbound throttling + 429 backoff.** `throttle.ts` serialises per-provider calls and honours `Retry-After` / exponential backoff — thoughtful for free-tier quotas (VirusTotal ~4/min is correctly spaced at 15 s).
- **Inbound rate limiting.** Zero-dependency sliding window with `Retry-After` and `X-RateLimit-*` headers; stricter bucket for `/api/scan/*`.
- **Graceful degradation.** crt.sh 502s are retried 3× then surfaced as a friendly "often overloaded" message rather than crashing.
- **Single-process deploy.** Server serves the built SPA with an `/api`-aware fallback, so one Render service runs the whole app. `render.yaml`, `Dockerfile`, and `DEPLOY.md` are all coherent.

---

## 3. Bugs & correctness issues

### 3.1 🔴 PWA icons are referenced but do not exist (broken install + apple-touch icon)

`client/index.html:11` and `client/public/manifest.webmanifest:11,17` reference `/icon-192.png` and `/icon-512.png`, but `client/public/` contains **only** `manifest.webmanifest` — and `client/dist/` confirms neither icon is emitted. Result: the PWA install prompt shows a broken icon, `apple-touch-icon` 404s, and the SPA fallback (`app.get('*')`) returns `index.html` (HTML) for those paths, so the browser gets a wrong-MIME response.

**Fix:** add real `icon-192.png` / `icon-512.png` (and a `favicon.ico`) to `client/public/`. A simple generated mark on the `#01696f` accent works. This is the highest-value 5-minute fix in the whole repo.

### 3.2 🟠 Exported HTML report silently drops most of the case

`exportHtmlReport` (`client/src/lib/workbench.ts:54`) renders only **entities** and **correlation hits**. It omits evidence, relationships, the timeline, and provenance — all of which the case already holds. A user exporting a "report" loses their evidentiary basis, which is the whole point of the tool.

**Fix:** include Evidence (title, URL, confidence, verified badge), Relationships, Timeline, and Provenance sections. Consider a print-friendly `@media print` stylesheet so it exports cleanly to PDF.

### 3.3 🟠 Export filenames are not sanitised (except GraphML)

- `exportHtmlReport` → `link.download = record.name + '.html'` (`workbench.ts:108`)
- `exportBundleZip` → `record.name + '.zip'` (`workbench.ts:121`)
- `downloadJson(activeCase, \`${activeCase.name}.json\`)` (`App.tsx`, report tab)

A case named `ACME / 2024 — breach` produces an invalid/odd filename. `sanitizeFilename()` already exists (`workbench.ts:50`) and is used only by `exportGraphML`. **Fix:** route all four exports through `sanitizeFilename`.

### 3.4 🟠 Re-running a lookup duplicates entities (no content-based dedupe)

`mergeProviderIntoCase` dedupes by `entity.id`, but every provider call mints fresh random IDs (`id('ent')` → `ent-<uuid8>`). So running free recon on `example.com` twice adds the same domain entity twice, with duplicate evidence. Cases bloat quickly with repeated lookups.

**Fix:** dedupe on a stable key — e.g. `type + '|' + name.toLowerCase()` (or the primary identifier) — merging identifiers/notes instead of appending a new entity.

### 3.5 🟡 `promoteConfidence` leaves stale verification metadata

`promoteEntityConfidence`/`promoteEvidenceConfidence` set `verified: false` but leave `verifiedAt`/`verifiedBy` populated. The UI then shows an unverified card that still reads "Verified by analyst · <time>". **Fix:** clear `verifiedAt`/`verifiedBy` when demoting.

### 3.6 🟡 Repeated Verify appends duplicate provenance entries

`verifyEntity`/`verifyEvidence` push a new provenance row on every click with no guard. Clicking Verify twice yields two identical "Analyst verified…" rows. **Fix:** skip if already verified, or upsert by `entityId`.

### 3.7 🟡 `buildGraphML` ignores correlation hits

The `_correlationHits` parameter (`workbench.ts:128`) is accepted and never used — the underscore signals it. GraphML export therefore can't represent cross-case links, which is the app's differentiator. **Fix:** emit correlation edges (or at least a `<data>` attribute) so the graph reflects cross-case matches.

### 3.8 🟡 `stats.attachments` is computed but never displayed

`App.tsx:144–153` counts attachments into `stats`, but the header only renders Cases / Correlation hits / Verified findings. Either surface it or drop the dead computation.

### 3.9 🟡 Unknown target type yields a silent empty result

`inferTargetType` returns `'username'` for anything unrecognised, and `runFreeRecon` has no branch for `username` → `results: []`. A user typing a bare username sees "Detected target type: username" and then nothing, with no hint that they should use the Sherlock lookup instead. **Fix:** return an explicit note ("no free providers apply to usernames — try the Sherlock lookup").

### 3.10 🟡 `lastProviders` React key can collide

`key={r.provider + r.query}` (`App.tsx:751`) — two results with the same provider+query (e.g. re-running a domain lookup) collide. Low impact, but use an index or a compound key.

---

## 4. Security & operational hardening

### 4.1 🟠 CORS is fully open
`app.use(cors())` (`server/src/index.ts:18`) allows any origin. For a public read-mostly tool this is low risk, but it means any site can drive your provider keys via the browser. **Fix:** default to same-origin and allow an `ALLOWED_ORIGINS` env allowlist.

### 4.2 🟠 Source maps shipped to production
`client/vite.config.ts:27` sets `sourcemap: true`, emitting a 911 kB `.map` that exposes full source. **Fix:** `sourcemap: process.env.NODE_ENV === 'production' ? false : true` (or `'hidden'` + upload to an error tracker).

### 4.3 🟡 Rate-limit key trusts spoofable `X-Forwarded-For`
`clientKey()` (`middleware/rateLimit.ts`) reads the first XFF entry. With `trust proxy = 1`, Express already resolves `req.ip` safely — prefer `req.ip`, else a client can rotate XFF to bypass the limiter.

### 4.4 🟡 One "free recon" click fans out to ~12+ upstream calls
`runFreeRecon` runs 5 providers concurrently, and DNS alone issues 6 DoH queries; crt.sh retries 3×. The inbound limiter counts this as **one** request, so the effective outbound amplification is high. **Fix:** add a per-provider outbound budget or count fan-out against the scan bucket.

### 4.5 🟡 No security headers
No `helmet`, no CSP. **Fix:** add `helmet()` with a modest CSP (the SPA needs `'self'` + inline styles). Also add `Referrer-Policy` and `X-Content-Type-Options`.

### 4.6 🟡 `/health` discloses env-var names
`server/src/index.ts:47` returns `envKey` for each provider. Not secret *values*, but it maps your configuration surface. Consider gating detailed health behind a token, or returning only `configured: true/false` counts.

### 4.7 🟡 No graceful shutdown
No `SIGTERM`/`SIGINT` handler. Render sends `SIGTERM` on redeploy; the process is killed mid-flight. **Fix:** capture signals, `server.close()`, exit.

### 4.8 🟡 Hardcoded version string
`version: '0.11.0'` in `index.ts:39` will drift from `package.json`. **Fix:** read from `package.json` at startup.

### 4.9 🟢 SSRF — checked, and clean
All providers hit **fixed** upstream hosts with the user input passed only as a query parameter (`lookupDns`, `lookupRdap`, `lookupWayback`, etc.). No user-controlled host is fetched, so there is no SSRF surface. Good.

---

## 5. UX & accessibility

- **No labels on inputs.** Every field relies on a placeholder (`App.tsx` lookup inputs). Placeholders vanish on typing and are invisible to screen readers. Add `<label>` (visually-hidden is fine) or `aria-label`.
- **`card-head` is a `<button>` containing block elements** (`<strong>`, `<span>`, `<small>`). Works, but is semantically odd; consider a heading + a real "Open" button, or `role="button"`.
- **No React error boundary.** One render exception blanks the entire app to a white screen. Wrap `<App/>` in an error boundary with a "reload / export data" fallback.
- **No light/dark toggle.** The app only follows `prefers-color-scheme`; power users on mobile often want to force one. A 3-state toggle (system/light/dark) persisted to `localStorage` is cheap.
- **Selects styled as pills.** `inputStyle` uses `borderRadius: 999` and is applied to `<select>` elements in the relationship editor, which looks off. Give selects a 12 px radius.
- **No empty-state guidance on the Lookup tab** for which target types map to which providers. A tiny legend ("domain → DNS/RDAP/CT/hostsearch/Wayback; IP → geo; email → Gravatar") would reduce trial-and-error.
- **No "copy" affordances** on identifiers/URLs — analysts copy these constantly.
- **Silent persistence failure.** `saveCases` swallows quota errors (`workbench.ts`), so a large case with data-URL attachments can silently fail to save and the user loses work on reload. **Fix:** detect `QuotaExceededError`, surface a banner, and offer JSON export.
- **`manifest` `background_color` is light-only** while the app supports dark mode — the splash will flash light for dark-mode users.
- **No `favicon.ico`** — browsers request it and get the SPA fallback HTML.

---

## 6. Architecture & maintainability

- **`App.tsx` is a 1,132-line monolith** holding all 8 tabs, all state, and all handlers. Split into `components/` + one file per tab (`CasesTab`, `LookupTab`, `EntitiesTab`, …), lifting shared state into a small store (Zustand or a `useReducer` context). This is the biggest maintainability win.
- **Duplicated types across the wire boundary.** `ProviderLookupResult`, `FreeReconResponse`, `SherlockScanResult`, etc. are declared in both `server/src/services/*` and `client/src/lib/workbench.ts`. Move the shared shapes into `shared/` (they already have Zod there) and import from one place.
- **`any` in the render path.** `(h: any, i: number)` at `App.tsx:729,758` defeats the `ProviderHit` type that already exists. Type the hit renderer once and reuse it for both lists.
- **`free.ts` `handle()` casts through a union** (`server/src/routes/free.ts`) to pull the single field out of a Zod result. Cleaner: pass the field name, or use a discriminated schema per route.
- **`prisma/schema.prisma` is a dead placeholder** (no Prisma dependency, no `DATABASE_URL`, not wired anywhere). It implies server persistence that doesn't exist. Either remove it or clearly comment "planned — not yet wired".
- **No tests.** Zero unit/integration tests. The pure functions are ideal low-hanging fruit: `inferTargetType`, `promoteConfidence`, `buildCorrelationHits`, `sanitizeFilename`, `mergeProviderIntoCase` dedupe, and the rate-limiter window logic. Add Vitest + a couple of provider-mock tests; even 20 tests would catch regressions in the verification ladder.
- **No CI.** Add a GitHub Actions workflow running `npm ci && npm run build && npm run lint && npm test` on PRs. Cheap insurance given Dependabot is already active.
- **`client/dist` appears committed/regenerated in the tree** — confirm it's git-ignored so build artifacts don't churn the repo.

---

## 7. Feature roadmap (highest value first)

**Tier 1 — completes the core loop**
1. **Case import (JSON round-trip).** Export exists; import doesn't. Without it, cases can't be shared, backed up, or restored — and the silent-quota issue has no recovery path. Add a drop-zone that validates against `caseSchema`.
2. **Real graph visualisation.** The "Graph" tab is currently a list of relationships. A force-directed SVG (or Cytoscape.js) showing entities as nodes, relationships + correlation as edges, colour-coded by confidence, would make the differentiator tangible.
3. **PDF report export.** HTML is fine for the web but deliverables want PDF. `wkhtmltopdf` is already installed in the sandbox; or use a print stylesheet + "Save as PDF".
4. **CSV export** of entities and evidence for spreadsheet triage.

**Tier 2 — more signal, still keyless**
5. **Shodan InternetDB** (`https://internetdb.shodan.io/{ip}`) — **free, no key**, returns open ports/CVEs/tags. High-value, trivial to add to the free set.
6. **IP RDAP** (`rdap.org/ip/{ip}`) and **reverse DNS / PTR** — rounds out IP recon with no key.
7. **urlscan.io** (free tier) and **CIRCL passive DNS** for domain history.
8. **TLS certificate inspection** (fetch the leaf cert for a host: issuer, SANs, validity) — pairs naturally with the existing CT work.

**Tier 3 — analyst workflow**
9. **Source-reliability rating** (Admiralty-style A–F × 1–6) alongside confidence — separates "how sure am I" from "how good is the source".
10. **Tags + filtering + case search** — cases grow fast; need a way to slice them.
11. **Activity/audit log** — every action with a timestamp, so the case file is defensible.
12. **Watchlist / re-scan reminders** — client-side "re-run this target" nudges (a server cron isn't viable on the free tier).
13. **Snapshot diffing** — compare two runs of the same target and highlight new/removed records.

**Tier 4 — reach**
14. **PWA offline shell** (service worker) so the UI loads offline and queues nothing sensitive.
15. **STIX 2.1 / MISP export** for threat-intel interop.
16. **Multi-provider "deep scan" orchestrator** with a progress stream (SSE) instead of blocking requests.

---

## 8. Prioritised quick-win checklist

| # | Fix | Effort | Impact |
|---|---|---|---|
| 1 | Add `icon-192.png`, `icon-512.png`, `favicon.ico` to `client/public/` | 15 min | 🔴 High |
| 2 | Sanitise all export filenames via `sanitizeFilename` | 15 min | 🟠 Med |
| 3 | Expand `exportHtmlReport` to include evidence/relationships/timeline/provenance | 1 h | 🟠 Med |
| 4 | Content-based entity dedupe in `mergeProviderIntoCase` | 1 h | 🟠 Med |
| 5 | Clear `verifiedAt/verifiedBy` on promote; guard duplicate verify provenance | 30 min | 🟡 Low |
| 6 | Restrict CORS via `ALLOWED_ORIGINS`; add `helmet` | 45 min | 🟠 Med |
| 7 | Disable prod source maps; read version from `package.json` | 20 min | 🟡 Low |
| 8 | Use `req.ip` for rate-limit key; add SIGTERM handler | 30 min | 🟡 Low |
| 9 | Case JSON **import** (round-trip) | 2 h | 🟠 Med |
| 10 | Add Vitest + tests for the pure functions; GitHub Actions CI | 3 h | 🟠 Med |
| 11 | Split `App.tsx` into tab components | 4 h | 🟡 Low (long-term high) |
| 12 | Add Shodan InternetDB + IP RDAP to free providers | 2 h | 🟢 Nice |

---

## 9. Suggested implementation order

1. **Ship the quick wins (1–8)** in a single "polish & hardening" PR — small, low-risk, visibly improves the product.
2. **Add case import + the expanded report** — closes the core loop (export ⇄ import, complete report).
3. **Add tests + CI** — locks in the verification-ladder behaviour before refactoring.
4. **Split `App.tsx`** into components once tests exist to catch regressions.
5. **Extend the free provider set** (InternetDB, IP RDAP, PTR, TLS) — more signal at zero key cost.
6. **Graph visualisation + PDF export** — the two features that most change how the tool *feels*.

---

*Prepared as a static review of v0.11.0. No source files were modified.*
