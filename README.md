# OSINT Workbench Platform

iOS-first OSINT web application monorepo with React/Vite client, Express API, shared Zod contracts, PWA shell, entity graph workflow, cross-case correlation, Sherlock username enumeration, GraphML export, and evidence package export.

**Version:** 0.7.0

## Stack
- React + Vite + TypeScript (client)
- Express + TypeScript (API + production static host)
- Shared Zod schemas/types
- PWA metadata for iPhone Safari / Add to Home Screen
- JSZip evidence bundles
- GraphML export (Maltego / Gephi / yEd)
- Sherlock CLI or Node fallback for username enumeration

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
- Cross-case token correlation (normalized identifiers; POSSIBLE only)
- Sherlock scan (Graph tab) merges evidence + entities + provenance
- Exports: Case JSON, HTML report, GraphML, ZIP bundle (includes GraphML)
- Archive preference: evidence carries archiveUrl (Wayback template)

## Confidence rules

- Tools never set VERIFIED
- Hits are POSSIBLE with Low–Medium confidence
- GraphML verification attributes are always POSSIBLE_*

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
Dockerfile  multi-stage production image
```

## Environment

```
DATABASE_URL="file:./dev.db"
PORT=8787
```
