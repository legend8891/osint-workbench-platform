import cors from 'cors';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { sampleApiCaseResponse } from './routes/sample.js';
import { scanRouter } from './routes/scan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'osint-workbench-api',
    version: '0.7.0',
    providers: ['sherlock'],
  });
});

app.get('/api/cases/sample', (_req, res) => {
  res.json(sampleApiCaseResponse);
});

app.use('/api/scan', scanRouter);

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
  console.log(`  Health:  GET  /health`);
  console.log(`  Sherlock: POST /api/scan/sherlock`);
});
