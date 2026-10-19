# OSINT Workbench Platform

iOS-first OSINT web application monorepo with React/Vite client, Express API, shared Zod contracts, PWA shell, entity graph workflow, cross-case correlation, Sherlock username enumeration, **free no-key recon**, an **analyst verification workflow**, GraphML export, and evidence package export.

**Version:** 0.12.0

## Stack
- React + Vite + TypeScript (client)
- Express + TypeScript (API + production static host)
- Shared Zod schemas/types
- PWA metadata for iPhone Safari / Add to Home Screen
- JSZip evidence bundles
- GraphML export (Maltego / Gephi / yEd)
- Sherlock CLI or Node fallback for username enumeration
- Vitest + GitHub Actions CI

## What's new in 0.12
- **Two more keyless providers** — **Shodan InternetDB** (open ports, CVEs, hostnames, tags for an IP) and **IP RDAP** (registered network block, country, org). Both need no API key.
- **Case import** — round-trip a previously exported case JSON straight back into the workbench, validated against the shared schema.
- **Security hardening** — `helmet` security headers + a strict Content-Security-Policy, opt-in CORS allow-list via `ALLOWED_ORIGINS`, rate-limit keyed on the trusted client IP, production source maps off, and graceful `SIGTERM`/`SIGINT` shutdown.
- **Version from `package.json`** — `/health` no longer hard-codes the version (and no longer leaks env-var names).
- **Richer exports** — the HTML report now includes evidence, relationships, timeline, provenance and cross-case correlation with print-friendly CSS; every export filename is sanitised.
- **Smarter merging** — provider results de-duplicate entities by type+name (unioning identifiers) and never downgrade an analyst-verified finding.
- **GraphML correlation** — exported graphs now carry a per-node `correlation` data key.
- **Tests + CI** — 40 Vitest unit tests over the pure logic, and a GitHub Actions workflow that builds, lints and tests on every push/PR.

## What's new in 0.11
- **Free recon (no API keys)** — DNS-over-HTTPS, RDAP WHOIS, certificate transparency (crt.sh), HackerTarget host search, IP geolocation (ipwho.is), Gravatar, and the Wayback Machine. Works out of the box.
- **Auto-detect target type** — one endpoint classifies a domain / IP / email / URL and runs the applicable free providers.
- **Analyst verification workflow** — promote confidence one rung at a time, or mark a finding *verified* (pinned to High, stamped with who/when, and recorded in provenance). Tools never verify.
- **Persistence** — cases survive a page reload (localStorage).
- **Case management** — rename and delete cases.
- **Relationship editor** — link entities in the Graph tab.
- **Confidence colour-coding** and provider status chips in the header.

## Quick start (development)

```bash
cd osint-workbench-platform
npm install
npm run dev
```

| Service | URL |
|---------|-----|
| Client UI | http://localhost:5173 |
| API health | http://localhost:8787/health |
| Free recon | `POST /api/scan/free` |
| Sherlock | `POST /api/scan/sherlock` |

Or: `./scripts/dev-bootstrap.sh`

## Production (single process)

Builds client into `client/dist` and serves it from Express on one port:

```bash
npm install
npm run build
npm start
# → http://localhost:8787
```

Or: `./scripts/prod-start.sh`

Set `PORT` if needed: `PORT=3000 npm start`

## Docker

```bash
docker build -t osint-workbench .
docker run --rm -p 8787:8787 osint-workbench
# → http://localhost:8787
```

Without Sherlock CLI, the Node fallback still works. Extend the image with `pipx install sherlock-project` for the full site list.

## Features

- Cases / entities / evidence / timeline / provenance
- **Free no-key recon** (DNS, RDAP, CT logs, host search, IP geo, Shodan InternetDB, IP RDAP, Gravatar, Wayback) with auto-detect
- **Analyst verification workflow** with confidence ladder (Unverified → Low → Medium → High)
- **Persistence** (localStorage) + case rename / delete + **case JSON import**
- **Relationship editor** for the entity graph
- Cross-case token correlation (normalized identifiers; POSSIBLE only)
- Sherlock scan merges evidence + entities + provenance
- Exports: Case JSON, HTML report, GraphML (with correlation), ZIP bundle (includes GraphML)
- Archive preference: evidence carries archiveUrl (Wayback template)

## Free recon endpoints (no API key)

| Endpoint | Input | Provider |
|----------|-------|----------|
| `POST /api/scan/free` | `{ "target": "example.com" }` | auto-detect (runs all applicable) |
| `POST /api/scan/dns` | `{ "domain": "example.com" }` | Cloudflare DNS-over-HTTPS |
| `POST /api/scan/rdap` | `{ "domain": "example.com" }` | RDAP (rdap.org) |
| `POST /api/scan/crtsh` | `{ "domain": "example.com" }` | crt.sh certificate transparency |
| `POST /api/scan/hostsearch` | `{ "domain": "example.com" }` | HackerTarget host search |
| `POST /api/scan/ipgeo` | `{ "ip": "1.1.1.1" }` | ipwho.is geolocation |
| `POST /api/scan/internetdb` | `{ "ip": "1.1.1.1" }` | Shodan InternetDB (ports/CVEs/tags) |
| `POST /api/scan/iprdap` | `{ "ip": "8.8.8.8" }` | IP RDAP (network block / country / org) |
| `POST /api/scan/gravatar` | `{ "email": "a@b.com" }` | Gravatar profile |
| `POST /api/scan/wayback` | `{ "target": "example.com" }` | Wayback Machine availability |

Example:

```bash
curl -s -X POST http://localhost:8787/api/scan/free \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

## Confidence rules

- Tools never set VERIFIED
- Hits are POSSIBLE with Low–Medium confidence
- An analyst can *promote* confidence one step or mark a finding *verified* (→ High)
- Verified records store `verified`, `verifiedAt`, `verifiedBy` and append a provenance entry
- GraphML verification attributes are always POSSIBLE_*

## Keyed providers (optional)

Paid providers activate only when their server environment keys are set; otherwise they return an explicit error and never fake data. See `.env.example` for the full list (HIBP, Hunter, Shodan, VirusTotal, AbuseIPDB, Numverify).

## Sherlock

```bash
pipx install sherlock-project   # optional

curl -s -X POST http://localhost:8787/api/scan/sherlock \
  -H 'Content-Type: application/json' \
  -d '{"usernames":["alexmorgan"]}'
```

## Maltego bridge

1. Export GraphML from the Report tab (or ZIP).
2. Import into Maltego / Gephi / yEd.
3. Optional: local maltego-trx transforms calling /api/scan/sherlock.

## Layout

```
client/     React UI + PWA
server/     Express API + static host in production
shared/     Zod schemas & types
prisma/     SQLite placeholder
scripts/    dev-bootstrap.sh, prod-start.sh
.github/    GitHub Actions CI (build · lint · test)
Dockerfile  multi-stage production image
```

## Environment

```
DATABASE_URL="file:./dev.db"
PORT=8787
# Optional: comma-separated origins allowed to call the API cross-origin.
# Leave unset to allow all (same-origin deployments don't need it).
ALLOWED_ORIGINS=
# Optional paid providers — leave blank to disable
HIBP_API_KEY=
HUNTER_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
NUMVERIFY_API_KEY=
SPIDERFOOT_BIN=
```

## Testing & CI

```bash
npm test        # Vitest unit tests (shared + client + server pure logic)
npm run lint    # ESLint (flat config) across client and server
npm run build   # shared → client → server
```

`.github/workflows/ci.yml` runs `npm ci` → build → lint → test on every push and pull request to `main`.

## Security notes

- `helmet` sets a strict Content-Security-Policy plus the usual hardening headers. The SPA is fully self-contained (no external assets), so `default-src 'self'` is safe.
- CORS is open only when `ALLOWED_ORIGINS` is unset; set it to lock the API to specific origins.
- Rate limiting keys on the trusted client IP (`trust proxy` + `req.ip`), not a spoofable header.
- Production builds ship **without** source maps. Set `SOURCEMAP=true` to opt in when debugging a deployed build.
