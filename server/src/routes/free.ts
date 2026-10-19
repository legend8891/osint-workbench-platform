import { Router } from 'express';
import { z } from 'zod';
import {
  lookupCrtSh,
  lookupDns,
  lookupGravatar,
  lookupHostSearch,
  lookupInternetDb,
  lookupIpGeo,
  lookupIpRdap,
  lookupRdap,
  lookupWayback,
  runFreeRecon,
} from '../services/freerecon.js';

export const freeRouter = Router();

const domainSchema = z.object({ domain: z.string().min(1).max(253) });
const ipSchema = z.object({ ip: z.string().min(3).max(45) });
const emailSchema = z.object({ email: z.string().email().max(254) });
const targetSchema = z.object({ target: z.string().min(1).max(512) });

function handle(
  schema: z.ZodTypeAny,
  run: (value: string) => Promise<unknown>,
  label: string
) {
  return async (req: import('express').Request, res: import('express').Response) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid body', details: parsed.error.flatten() });
      return;
    }
    const value = String(
      (parsed.data as { domain?: string; ip?: string; email?: string; target?: string }).domain ??
        (parsed.data as { ip?: string }).ip ??
        (parsed.data as { email?: string }).email ??
        (parsed.data as { target?: string }).target ??
        ''
    );
    try {
      res.json(await run(value));
    } catch (err) {
      res.status(500).json({
        error: `${label} failed`,
        message: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  };
}

/** Combined free recon — auto-detects target type, runs all applicable providers. */
freeRouter.post('/free', handle(targetSchema, runFreeRecon, 'Free recon'));

/** DNS records via Cloudflare DoH. */
freeRouter.post('/dns', handle(domainSchema, lookupDns, 'DNS lookup'));

/** RDAP domain registration. */
freeRouter.post('/rdap', handle(domainSchema, lookupRdap, 'RDAP lookup'));

/** Certificate Transparency subdomains via crt.sh. */
freeRouter.post('/crtsh', handle(domainSchema, lookupCrtSh, 'crt.sh lookup'));

/** Subdomain discovery via HackerTarget hostsearch. */
freeRouter.post('/hostsearch', handle(domainSchema, lookupHostSearch, 'HackerTarget lookup'));

/** IP geolocation via ipwho.is. */
freeRouter.post('/ipgeo', handle(ipSchema, lookupIpGeo, 'IP geolocation'));

/** Shodan InternetDB exposure (open ports, CVEs, tags) for an IP. */
freeRouter.post('/internetdb', handle(ipSchema, lookupInternetDb, 'InternetDB lookup'));

/** IP RDAP registration (network block, country, org) for an IP. */
freeRouter.post('/iprdap', handle(ipSchema, lookupIpRdap, 'IP RDAP lookup'));

/** Gravatar profile for an email. */
freeRouter.post('/gravatar', handle(emailSchema, lookupGravatar, 'Gravatar lookup'));

/** Wayback Machine availability. */
freeRouter.post('/wayback', handle(targetSchema, lookupWayback, 'Wayback lookup'));
