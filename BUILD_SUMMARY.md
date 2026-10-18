# OSINT Workbench Platform — v0.11.0 Build Summary

**Repo:** `Legend8891/osint-workbench-platform` (the most developed *original* OSINT project on the account — 65 own commits; all other OSINT repos are forks with 0–1 own commits).
**Release:** 0.11.0 (from 0.7.0/0.8.0)
**Status:** ✅ Builds clean, server runs, all new endpoints + UI flows smoke-tested.

---

## Why this repo
Using the GitHub API I compared every repo on the account. Only two are original work:
- `osint-workbench-platform` — 65 own commits, full TypeScript monorepo (React + Express + shared Zod).
- `SAAS_OSINT` — 4 commits (stub).

Everything else (`spiderfoot`, `maigret`, `web-check`, `Mr.Holmes`, `user-scanner`, `mantis-posture`) is a **fork** with 0–1 own commits. So `osint-workbench-platform` is the right thing to keep building.

## Problems found (gap analysis)
1. **Almost nothing worked out of the box** — nearly every provider (HIBP, Hunter, Shodan, VirusTotal, AbuseIPDB, Numverify) needed a *paid* API key. Only Sherlock ran keyless.
2. **No verification workflow** — the app's whole philosophy is *"POSSIBLE until verified"*, but there was no way to actually verify anything.
3. **No persistence** — every case vanished on page reload.
4. **No case management** — couldn't rename or delete a case.
5. **SpiderFoot was wired on the server but not in the UI.**
6. **No relationship creation** and no confidence colour-coding.

## What was built

### 1. Free, no-key recon (the big win — usable immediately)
Seven new providers that need **zero API keys**, all with graceful failure:
| Provider | Source | Endpoint |
|---|---|---|
| DNS | Cloudflare DNS-over-HTTPS | `POST /api/scan/dns` |
| RDAP WHOIS | rdap.org | `POST /api/scan/rdap` |
| Certificate transparency | crt.sh | `POST /api/scan/crtsh` |
| Host search | HackerTarget | `POST /api/scan/hostsearch` |
| IP geolocation | ipwho.is | `POST /api/scan/ipgeo` |
| Gravatar | gravatar.com | `POST /api/scan/gravatar` |
| Wayback Machine | archive.org | `POST /api/scan/wayback` |

Plus a **combined auto-detect** endpoint `POST /api/scan/free` that classifies the target (domain / IP / email / URL) and runs every applicable provider in one shot. New file: `server/src/services/freerecon.ts` (780 lines) + `server/src/routes/free.ts`.

All results flow through the existing throttle/backoff and merge into the active case as entities + evidence + provenance.

### 2. Analyst verification workflow
- Shared schema gained `verified`, `verifiedAt`, `verifiedBy` on entities **and** evidence, plus a `CONFIDENCE_ORDER` ladder and `promoteConfidence()` helper.
- New client actions per finding: **Promote ▲** (one rung up), **Verify ✓** (pins to High, stamps who/when, appends a provenance entry), **Unverify**, **Delete**.
- Tools *never* auto-verify — only the analyst can, preserving the "POSSIBLE until verified" invariant.

### 3. Persistence & case management
- Cases persist to `localStorage` (`osint-workbench-cases-v1`) and survive reloads.
- Rename and delete cases from the Cases tab.

### 4. UI polish
- Confidence **badges** (High/Medium/Low/Unverified) with colour coding.
- **Verified cards** get a highlighted border.
- **Provider status chips** in the header (version, free providers, keyed, missing keys) fed by `/health`.
- **Relationship editor** in the Graph tab (link two entities with a typed relationship).
- Free recon and SpiderFoot are now **wired into the Lookup tab**.
- Fixed the tab grid (was hard-coded to 7 columns for 8 tabs → now `auto-fit`).

### 5. Docs & versions
- README rewritten to document free recon, verification, persistence, and endpoints.
- `.env.example` notes that free recon needs no keys.
- All package versions bumped to 0.11.0.

## Verification performed
- `npm run build` — clean, **no TypeScript errors**.
- Server boots on port 8787; `/health` reports `version 0.11.0`, `freeProviders: [dns, rdap, crtsh, hostsearch, ipgeo, gravatar, wayback]`.
- Live smoke tests (via curl **and** the browser):
  - `example.com` → DNS (9 records), RDAP (9), HackerTarget (1), Wayback (1); crt.sh degrades gracefully.
  - `github.com` → DNS (34), RDAP (15), HackerTarget (14), Wayback (1).
  - `8.8.8.8` → auto-detected as `ip` → ipwho.is geo (San Jose, Google LLC).
  - `test@gmail.com` → auto-detected as `email` → Gravatar.
  - UI: created a case → ran free recon → merged findings → **verified** an entity (→ High ✓, "Verified by analyst", provenance entry, stat "Verified findings: 1") → **reloaded** and confirmed persistence → added a relationship → renamed the case.

## Files changed
```
shared/src/index.ts               verification fields + confidence helpers
server/src/services/freerecon.ts  7 free providers + auto-detect  (NEW)
server/src/routes/free.ts         /api/scan/* free routes         (NEW)
server/src/services/framework.ts  "Free Recon (no key)" catalog category
server/src/index.ts               mount free router, health, v0.11.0
client/src/lib/workbench.ts       persistence, verification, case mgmt, relationships, free wrappers
client/src/pages/App.tsx          full rewrite of the UI
client/src/styles/app.css         badges, chips, verified/selected cards, action variants
README.md / .env.example          docs
package.json (+ workspaces)       version 0.11.0
```

## How to run
```bash
cd osint-workbench-platform
npm install
npm run build
npm start          # → http://localhost:8787
```
Or for development: `npm run dev` (client on :5173, API on :8787).

## Notes / limitations
- **crt.sh** is frequently overloaded (returns HTTP 502) and is blocked from this particular sandbox; the code retries 3× with backoff and then reports a friendly "try again shortly" message. It works from normal networks.
- **SpiderFoot** needs the CLI on the host (`SPIDERFOOT_BIN`) — not available on typical free hosting.
- The public port-exposure URL did not route in this sandbox (CloudFront returned 403); run locally with the commands above.
