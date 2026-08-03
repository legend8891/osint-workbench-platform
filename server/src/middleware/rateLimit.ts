/**
 * Inbound rate limiting (per client IP) for API routes.
 * Zero-dependency sliding window.
 *
 * Env:
 *   RATE_LIMIT_WINDOW_MS   default 60000 (1 min)
 *   RATE_LIMIT_MAX         default 30 requests / window / api bucket
 *   RATE_LIMIT_SCAN_MAX    default 12  (stricter for /api/scan/*)
 */

import type { Request, Response, NextFunction } from 'express';

type Bucket = { timestamps: number[] };

const buckets = new Map<string, Bucket>();

function windowMs(): number {
  const n = Number(process.env.RATE_LIMIT_WINDOW_MS);
  return Number.isFinite(n) && n > 0 ? n : 60_000;
}

function maxForPath(path: string): number {
  const isScan = path.startsWith('/api/scan');
  const envKey = isScan ? 'RATE_LIMIT_SCAN_MAX' : 'RATE_LIMIT_MAX';
  const fallback = isScan ? 12 : 30;
  const n = Number(process.env[envKey]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function clientKey(req: Request): string {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0]!.trim();
  if (Array.isArray(xf) && xf[0]) return String(xf[0]).split(',')[0]!.trim();
  return req.socket.remoteAddress || 'unknown';
}

function prune(now: number, win: number) {
  if (buckets.size < 500) return;
  for (const [k, b] of buckets) {
    b.timestamps = b.timestamps.filter((t) => now - t < win);
    if (b.timestamps.length === 0) buckets.delete(k);
  }
}

export function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.path === '/health') {
    next();
    return;
  }
  if (!req.path.startsWith('/api')) {
    next();
    return;
  }

  const win = windowMs();
  const max = maxForPath(req.path);
  const now = Date.now();
  const key = `${clientKey(req)}:${req.path.startsWith('/api/scan') ? 'scan' : 'api'}`;

  prune(now, win);

  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { timestamps: [] };
    buckets.set(key, bucket);
  }
  bucket.timestamps = bucket.timestamps.filter((t) => now - t < win);

  if (bucket.timestamps.length >= max) {
    const oldest = bucket.timestamps[0]!;
    const retryAfterSec = Math.max(1, Math.ceil((oldest + win - now) / 1000));
    res.setHeader('Retry-After', String(retryAfterSec));
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', '0');
    res.setHeader('X-RateLimit-Reset', String(Math.ceil((oldest + win) / 1000)));
    res.status(429).json({
      error: 'rate_limited',
      message: `Too many requests. Try again in ${retryAfterSec}s.`,
      retryAfterSec,
      limit: max,
      windowMs: win,
    });
    return;
  }

  bucket.timestamps.push(now);
  res.setHeader('X-RateLimit-Limit', String(max));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - bucket.timestamps.length)));
  next();
}
