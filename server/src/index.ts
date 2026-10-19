import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { sampleApiCaseResponse } from './routes/sample.js';
import { scanRouter } from './routes/scan.js';
import { freeRouter } from './routes/free.js';
import { frameworkRouter } from './routes/framework.js';
import { getProviderStatuses } from './services/framework.js';
import { FREE_PROVIDER_IDS } from './services/freerecon.js';
import { rateLimitMiddleware } from './middleware/rateLimit.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/** Version is read from the server package.json so /health never drifts. */
function readVersion(): string {
  try {
    const pkgPath = path.resolve(__dirname, '../package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
const VERSION = readVersion();

app.set('trust proxy', 1);

/**
 * CORS: lock down cross-origin access when ALLOWED_ORIGINS is set
 * (comma-separated). Same-origin and non-browser (no Origin header)
 * requests are always allowed. When unset, all origins are allowed so
 * existing single-process deployments keep working.
 */
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`Origin ${origin} is not allowed by CORS`));
    },
  })
);

/** Security headers. The SPA is fully self-contained (no external assets). */
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(rateLimitMiddleware);

const LIVE_PROVIDER_IDS = new Set([
  'hibp',
  'hunterio',
  'shodan',
  'virustotal',
  'abuseipdb',
  'numverify',
  'sherlock',
]);

app.get('/health', (_req, res) => {
  const providers = getProviderStatuses();
  const live = providers.filter((p) => LIVE_PROVIDER_IDS.has(p.id));
  const free = providers.filter((p) => (FREE_PROVIDER_IDS as readonly string[]).includes(p.id));
  res.json({
    ok: true,
    service: 'osint-workbench-api',
    version: VERSION,
    rateLimit: {
      windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,
      maxApi: Number(process.env.RATE_LIMIT_MAX) || 30,
      maxScan: Number(process.env.RATE_LIMIT_SCAN_MAX) || 12,
    },
    keys: live.map((p) => ({
      id: p.id,
      configured: p.configured,
    })),
    providersConfigured: live.filter((p) => p.configured).map((p) => p.id),
    providersMissing: live.filter((p) => !p.configured && p.envKey !== '(none)').map((p) => p.id),
    freeProviders: free.map((p) => p.id),
    framework: {
      categories: true,
      path: '/api/framework',
    },
    freeRecon: {
      path: '/api/scan/free',
      note: 'No API keys required. Auto-detects target type (domain/IP/email/URL).',
      providers: [...FREE_PROVIDER_IDS],
    },
    spiderfoot: {
      path: '/api/scan/spiderfoot',
      note: 'Requires SpiderFoot CLI on host (SPIDERFOOT_BIN). Not available on typical free Render.',
    },
  });
});

app.get('/api/cases/sample', (_req, res) => {
  res.json(sampleApiCaseResponse);
});

app.use('/api/scan', scanRouter);
app.use('/api/scan', freeRouter);
app.use('/api/framework', frameworkRouter);

const clientDist = path.resolve(__dirname, '../../client/dist');
if (existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path === '/health') return next();
    res.sendFile(path.join(clientDist, 'index.html'));
  });
  console.log(`Serving client static from ${clientDist}`);
}

const PORT = Number(process.env.PORT) || 8787;
const server = app.listen(PORT, () => {
  console.log(`OSINT Workbench v${VERSION} listening on http://localhost:${PORT}`);
  console.log(`  Health:     GET  /health`);
  console.log(`  Framework:  GET  /api/framework`);
  console.log(`  Sherlock:   POST /api/scan/sherlock`);
  console.log(`  SpiderFoot: POST /api/scan/spiderfoot`);
  console.log(`  Free recon: POST /api/scan/free (no keys)`);
  console.log(`  Email:      POST /api/scan/email`);
  console.log(`  Domain/IP:  POST /api/scan/hunter|shodan|...`);
  console.log(
    `  Rate limit: ${Number(process.env.RATE_LIMIT_SCAN_MAX) || 12}/min scan, ${Number(process.env.RATE_LIMIT_MAX) || 30}/min other API`
  );
  if (allowedOrigins.length > 0) {
    console.log(`  CORS:       restricted to ${allowedOrigins.join(', ')}`);
  }
});

/** Graceful shutdown so in-flight requests finish before the process exits. */
function shutdown(signal: string) {
  console.log(`\n${signal} received — shutting down gracefully…`);
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
  // Force-exit if connections linger.
  setTimeout(() => {
    console.error('Forcing exit after timeout.');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
