import cors from 'cors';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { sampleApiCaseResponse } from './routes/sample.js';
import { scanRouter } from './routes/scan.js';
import { frameworkRouter } from './routes/framework.js';
import { getProviderStatuses } from './services/framework.js';
import { rateLimitMiddleware } from './middleware/rateLimit.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimitMiddleware);

app.get('/health', (_req, res) => {
  const providers = getProviderStatuses();
  res.json({
    ok: true,
    service: 'osint-workbench-api',
    version: '0.10.0',
    rateLimit: {
      windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,
      maxApi: Number(process.env.RATE_LIMIT_MAX) || 30,
      maxScan: Number(process.env.RATE_LIMIT_SCAN_MAX) || 12,
    },
    providers: providers.filter((p) => p.configured).map((p) => p.id),
    framework: {
      categories: true,
      path: '/api/framework',
    },
  });
});

app.get('/api/cases/sample', (_req, res) => {
  res.json(sampleApiCaseResponse);
});

app.use('/api/scan', scanRouter);
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
app.listen(PORT, () => {
  console.log(`OSINT Workbench listening on http://localhost:${PORT}`);
  console.log(`  Health:     GET  /health`);
  console.log(`  Framework:  GET  /api/framework`);
  console.log(`  Sherlock:   POST /api/scan/sherlock`);
  console.log(`  Email:      POST /api/scan/email`);
  console.log(`  Domain/IP:  POST /api/scan/hunter|shodan|...`);
  console.log(
    `  Rate limit: ${Number(process.env.RATE_LIMIT_SCAN_MAX) || 12}/min scan, ${Number(process.env.RATE_LIMIT_MAX) || 30}/min other API`
  );
});
