# Deploying OSINT Workbench Platform

The app is a **single Node process** that serves both the API and the built React UI on one port (default `8787`). That makes it easy to host anywhere Node runs.

```
npm install && npm run build && npm start   # → http://localhost:8787
```

---

## Option 1 — Render (recommended, free tier, one click)

A `render.yaml` blueprint is already in the repo.

1. Push this repo to GitHub (see "Push to GitHub" below).
2. Go to **https://render.com** → **New +** → **Blueprint**.
3. Connect your GitHub account and pick the `osint-workbench-platform` repo.
4. Render reads `render.yaml` automatically:
   - Build: `npm install && npm run build`
   - Start: `npm start`
   - Health check: `/health`
   - Plan: **Free**
5. (Optional) Add paid-provider keys under **Environment** — the free recon providers work with **no keys at all**:
   `HIBP_API_KEY`, `HUNTER_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `NUMVERIFY_API_KEY`.
6. Click **Create Web Service**. First build takes ~2–4 min. You'll get a URL like `https://osint-workbench-platform.onrender.com`.

> Free-tier note: Render free services sleep after ~15 min idle; the first request after that takes ~30s to wake.

---

## Option 2 — Docker (any host: Fly.io, Railway, a VPS, your laptop)

A multi-stage `Dockerfile` (Node 20) is included.

```bash
# Build
docker build -t osint-workbench .

# Run
docker run --rm -p 8787:8787 osint-workbench
# → http://localhost:8787
```

With API keys:

```bash
docker run --rm -p 8787:8787 \
  -e HIBP_API_KEY=xxx -e SHODAN_API_KEY=xxx \
  osint-workbench
```

Push to a registry and deploy to Fly.io / Railway / Cloud Run / any VPS the same way.

---

## Option 3 — Any Node host (Railway, Fly.io, Heroku-style, VPS)

- **Build command:** `npm install && npm run build`
- **Start command:** `npm start`  (or `node server/dist/index.js`)
- **Node version:** 20 (`engines` requires `>=20 <23`)
- **Port:** the server reads `PORT` from the environment (Render sets `10000`; the Dockerfile defaults to `8787`).
- **Health check path:** `/health`

### Plain VPS (Ubuntu) with pm2

```bash
# on the server
git clone https://github.com/Legend8891/osint-workbench-platform.git
cd osint-workbench-platform
npm install && npm run build
npm install -g pm2
PORT=8787 pm2 start server/dist/index.js --name osint-workbench
pm2 save && pm2 startup
```

Put Nginx/Caddy in front for TLS on port 80/443.

---

## Option 4 — Static-only note

The client is a static Vite build (`client/dist`), but the app **needs the Express API** for lookups (free recon, Sherlock, etc.). So host it as a **Node app**, not as a pure static site. If you only want to preview the UI shell, `client/dist` can be served by any static host, but lookups will fail without the API.

---

## Push to GitHub

The two new commits are ready locally. Authenticate once, then push:

```bash
cd osint-workbench-platform
git push origin main
```

If prompted for credentials, use a **Personal Access Token** (classic, scope `repo`) as the password, or run `gh auth login`.

---

## Environment variables (all optional)

| Variable | Purpose |
|---|---|
| `PORT` | Server port (default `8787`) |
| `NODE_ENV` | `production` |
| `HIBP_API_KEY` | Have I Been Pwned (email breaches) |
| `HUNTER_API_KEY` | Hunter.io (email/domain) |
| `SHODAN_API_KEY` | Shodan (IP) |
| `VIRUSTOTAL_API_KEY` | VirusTotal (domain/IP) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (IP reputation) |
| `NUMVERIFY_API_KEY` | Numverify (phone) |
| `SPIDERFOOT_BIN` | Path to SpiderFoot CLI (optional) |

**Free recon (DNS, RDAP, crt.sh, HackerTarget, IP geo, Gravatar, Wayback) requires no keys and is enabled by default.**
