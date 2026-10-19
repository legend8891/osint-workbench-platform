# OSINT Workbench Platform — v0.12.0 Build Summary

**Repo:** `Legend8891/osint-workbench-platform`
**Release:** 0.12.0 (from 0.11.0)
**Status:** ✅ Builds clean, lints clean, 40/40 tests pass, server runs, new endpoints smoke-tested.

This release implements the improvement plan from `REVIEW.md`: a set of quick-win fixes, a completed core loop, two new keyless providers, and a real test + CI story.

---

## Phase A — Quick wins (polish & hardening)

| # | Change | Where |
|---|--------|-------|
| A1 | **PWA icons** — added `icon-192.png`, `icon-512.png`, `favicon.ico`, `apple-touch-icon.png`; manifest now points at real files with a dark `background_color`. | `client/public/*`, `client/index.html`, `manifest.webmanifest` |
| A2 | **Filename sanitising** — every export (JSON, HTML, GraphML, ZIP) runs the case name through `sanitizeFilename`. | `client/src/lib/workbench.ts` |
| A3 | **Full HTML report** — now renders entities, evidence, relationships, timeline, provenance and cross-case correlation, with print-friendly CSS and confidence badges. | `client/src/lib/workbench.ts` |
| A4 | **Content-based entity dedupe** — provider results merge by `type\|name`, unioning identifiers instead of minting duplicates. | `client/src/lib/workbench.ts` |
| A5 | **Verification integrity** — promoting confidence clears `verifiedAt`/`verifiedBy`; re-verifying is idempotent (no duplicate provenance). | `client/src/lib/workbench.ts` |
| A6 | **Security headers + CORS** — `helmet` with a strict CSP; CORS allow-list via `ALLOWED_ORIGINS`. | `server/src/index.ts` |
| A7 | **Source maps off + real version** — production builds ship no `.map`; `/health` reads the version from `package.json`. | `client/vite.config.ts`, `server/src/index.ts` |
| A8 | **Trusted rate-limit key + graceful shutdown** — rate limiting keys on `req.ip`; `SIGTERM`/`SIGINT` close the server cleanly. | `server/src/middleware/rateLimit.ts`, `server/src/index.ts` |

## Phase B — Core loop

- **B1 — Case import.** Export a case to JSON, then import it back through the shared Zod schema (`parseImportedCase`), with a unique-id guard (`withUniqueId`) and a readable error banner. A storage-full warning now appears if `localStorage` writes fail.
- **B2 — GraphML correlation.** Exported graphs carry a per-node `correlation` data key listing the cross-case tokens an entity participates in.
- **B3 — Stats + unknown types.** The header now shows the (previously dead) attachments stat, and a free-recon run that matches no provider says so explicitly instead of failing silently.

## Phase C — Two new keyless providers

| Provider | Source | Endpoint | Returns |
|---|---|---|---|
| **Shodan InternetDB** | internetdb.shodan.io | `POST /api/scan/internetdb` | open ports, CVEs, hostnames, CPEs, tags |
| **IP RDAP** | rdap.org | `POST /api/scan/iprdap` | registered network block, country, org |

Both are wired into the combined `POST /api/scan/free` auto-detect (IP branch), the framework catalog, and `/health` (`freeProviders` now lists **9** ids).

## Phase D — Quality

- **D1 — Vitest.** 40 unit tests over the pure logic:
  - `shared`: confidence ladder, `isVerified`, `caseSchema` validation.
  - `client`: `sanitizeFilename`, `buildCorrelationHits`, `buildGraphML`, `mergeProviderIntoCase` (dedupe + verified-preservation), `parseImportedCase`/`withUniqueId`, case mutations, verification workflow.
  - `server`: `inferTargetType`, `FREE_PROVIDER_IDS`.
- **D2 — GitHub Actions CI.** `.github/workflows/ci.yml` runs `npm ci` → build → lint → test on every push/PR to `main`.
- **ESLint fixed.** The repo's `lint` script was broken (no config for ESLint 9). Added flat configs for client and server (`typescript-eslint` + `react-hooks`), fixed the 2 real errors they surfaced, and removed the 2 `any` warnings.

## Verification performed

- `npm ci` → `npm run build` → `npm run lint` → `npm test` — **all exit 0** from a clean install.
- Server boots; `/health` reports `version 0.12.0` and the 9 free providers.
- Response headers confirmed: `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy`, `X-Content-Type-Options`.
- Graceful shutdown confirmed: `SIGTERM` → "shutting down gracefully… HTTP server closed."
- Live smoke tests:
  - `1.1.1.1` → InternetDB (ports 53/80/443/…), IP RDAP (Cloudflare range).
  - `8.8.8.8` → auto-detected as `ip` → ipwho.is geo + InternetDB + IP RDAP (GOGL, 8.8.8.0–8.8.8.255, Google LLC).
  - `example.com` → DNS, RDAP, HackerTarget, Wayback (crt.sh degrades gracefully on 502).
  - `someusername` → 0 providers, with an explicit "no free provider matches" note.

## Files changed

```
shared/src/index.ts                     (unchanged this release; tests added)
shared/src/index.test.ts                (NEW) shared unit tests
server/src/index.ts                     helmet, CORS allow-list, version-from-pkg, graceful shutdown
server/src/middleware/rateLimit.ts      req.ip-based key
server/src/services/freerecon.ts        + InternetDB, + IP RDAP, auto-detect wiring
server/src/services/freerecon.test.ts   (NEW) server unit tests
server/src/services/framework.ts        register the two new providers
server/src/services/sherlock.ts         lint fix (regex escape)
server/src/services/spiderfoot.ts       lint fix (prefer-const)
server/src/routes/free.ts               /internetdb, /iprdap routes
server/eslint.config.js                 (NEW) flat config
client/src/lib/workbench.ts             sanitising, report, dedupe, import, GraphML, helpers
client/src/lib/workbench.test.ts        (NEW) client unit tests
client/src/pages/App.tsx                import UI, storage warning, attachments stat, HitLike type
client/src/styles/app.css               banner + responsive stats grid
client/src/public/*                     (NEW) PWA icons
client/index.html, manifest.webmanifest icon links
client/vite.config.ts                   source maps off by default
client/eslint.config.js                 (NEW) flat config
.github/workflows/ci.yml                (NEW) CI
vitest.config.ts                        (NEW) test config
package.json (+ workspaces)             version 0.12.0, test scripts
README.md / BUILD_SUMMARY.md / .gitignore
```

## How to run

```bash
cd osint-workbench-platform
npm install
npm run build
npm start          # → http://localhost:8787
```

Development: `npm run dev` (client on :5173, API on :8787).
Tests: `npm test`. Lint: `npm run lint`.

## Notes / limitations

- **crt.sh** is frequently overloaded (HTTP 502); the code retries 3× with backoff and then reports a friendly "try again shortly" message.
- **SpiderFoot** needs the CLI on the host (`SPIDERFOOT_BIN`) — not available on typical free hosting.
- **Shodan InternetDB** only covers IPs Shodan has seen; a 404 is a normal "no data" answer, surfaced as such.
- Previous release: see git history for the v0.11.0 summary (free recon + verification workflow).
