import { Router } from 'express';
import { z } from 'zod';
import { scanUsername, scanUsernames } from '../services/sherlock.js';

export const scanRouter = Router();

const bodySchema = z.object({
  usernames: z.array(z.string().min(1).max(64)).min(1).max(10),
});

scanRouter.post('/sherlock', async (req, res) => {
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid body',
      details: parsed.error.flatten(),
    });
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
