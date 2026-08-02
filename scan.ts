import { Router } from 'express';
import { z } from 'zod';
import { scanUsername, scanUsernames } from '../services/sherlock.js';
import {
  lookupAbuseIp,
  lookupHibp,
  lookupHunterDomain,
  lookupHunterEmail,
  lookupNumverify,
  lookupShodan,
  lookupVirusTotalDomain,
} from '../services/providers.js';

export const scanRouter = Router();

const usernamesSchema = z.object({
  usernames: z.array(z.string().min(1).max(64)).min(1).max(10),
});

scanRouter.post('/sherlock', async (req, res) => {
  const parsed = usernamesSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    const results =
      parsed.data.usernames.length === 1
        ? [await scanUsername(parsed.data.usernames[0])]
        : await scanUsernames(parsed.data.usernames);
    res.json({
      provider: 'sherlock',
      scannedAt: new Date().toISOString(),
      results,
      summary: {
        usernames: results.length,
        totalFound: results.reduce(
          (n, r) => n + r.hits.filter((h) => h.status === 'found').length,
          0
        ),
        mode: results[0]?.mode ?? 'unknown',
      },
    });
  } catch (err) {
    console.error('[scan/sherlock]', err);
    res.status(500).json({
      error: 'Scan failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

const emailSchema = z.object({ email: z.string().email().max(254) });
const domainSchema = z.object({ domain: z.string().min(1).max(253) });
const ipSchema = z.object({ ip: z.string().min(3).max(45) });
const phoneSchema = z.object({ phone: z.string().min(5).max(32) });

scanRouter.post('/hibp', async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupHibp(parsed.data.email));
  } catch (err) {
    res.status(500).json({
      error: 'HIBP failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/hunter/email', async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupHunterEmail(parsed.data.email));
  } catch (err) {
    res.status(500).json({
      error: 'Hunter failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/hunter/domain', async (req, res) => {
  const parsed = domainSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupHunterDomain(parsed.data.domain));
  } catch (err) {
    res.status(500).json({
      error: 'Hunter domain failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/numverify', async (req, res) => {
  const parsed = phoneSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupNumverify(parsed.data.phone));
  } catch (err) {
    res.status(500).json({
      error: 'Numverify failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/abuseipdb', async (req, res) => {
  const parsed = ipSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupAbuseIp(parsed.data.ip));
  } catch (err) {
    res.status(500).json({
      error: 'AbuseIPDB failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/virustotal/domain', async (req, res) => {
  const parsed = domainSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupVirusTotalDomain(parsed.data.domain));
  } catch (err) {
    res.status(500).json({
      error: 'VirusTotal failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/shodan', async (req, res) => {
  const parsed = ipSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  try {
    res.json(await lookupShodan(parsed.data.ip));
  } catch (err) {
    res.status(500).json({
      error: 'Shodan failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

scanRouter.post('/email', async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
    return;
  }
  const email = parsed.data.email;
  try {
    const [hibp, hunter] = await Promise.all([lookupHibp(email), lookupHunterEmail(email)]);
    res.json({
      query: email,
      scannedAt: new Date().toISOString(),
      results: [hibp, hunter],
    });
  } catch (err) {
    res.status(500).json({
      error: 'Email lookup failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});
