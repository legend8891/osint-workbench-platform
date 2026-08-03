/**
 * Outbound provider throttle + 429 backoff.
 * Serialises calls per provider so free-tier quotas are not burned.
 *
 * Env (ms between calls, per provider):
 *   THROTTLE_HIBP_MS          default 1600
 *   THROTTLE_HUNTER_MS        default 1200
 *   THROTTLE_SHODAN_MS        default 1000
 *   THROTTLE_VIRUSTOTAL_MS    default 15000  (free VT ~4/min)
 *   THROTTLE_ABUSEIPDB_MS     default 1200
 *   THROTTLE_NUMVERIFY_MS     default 800
 *   THROTTLE_DEFAULT_MS       default 500
 *   THROTTLE_MAX_RETRIES      default 2
 */

type ProviderId =
  | 'hibp'
  | 'hunter'
  | 'shodan'
  | 'virustotal'
  | 'abuseipdb'
  | 'numverify'
  | 'default';

const lastCallAt = new Map<string, number>();
const tails = new Map<string, Promise<unknown>>();

function minInterval(provider: ProviderId): number {
  const envMap: Record<ProviderId, string> = {
    hibp: 'THROTTLE_HIBP_MS',
    hunter: 'THROTTLE_HUNTER_MS',
    shodan: 'THROTTLE_SHODAN_MS',
    virustotal: 'THROTTLE_VIRUSTOTAL_MS',
    abuseipdb: 'THROTTLE_ABUSEIPDB_MS',
    numverify: 'THROTTLE_NUMVERIFY_MS',
    default: 'THROTTLE_DEFAULT_MS',
  };
  const defaults: Record<ProviderId, number> = {
    hibp: 1600,
    hunter: 1200,
    shodan: 1000,
    virustotal: 15_000,
    abuseipdb: 1200,
    numverify: 800,
    default: 500,
  };
  const n = Number(process.env[envMap[provider]]);
  return Number.isFinite(n) && n >= 0 ? n : defaults[provider];
}

function maxRetries(): number {
  const n = Number(process.env.THROTTLE_MAX_RETRIES);
  return Number.isFinite(n) && n >= 0 ? n : 2;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Queue fn so only one call runs at a time per provider, with min spacing. */
export async function withProviderThrottle<T>(
  provider: ProviderId,
  fn: () => Promise<T>
): Promise<T> {
  const prev = tails.get(provider) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const next = prev.then(() => gate);
  tails.set(
    provider,
    next.catch(() => undefined)
  );

  await prev.catch(() => undefined);

  try {
    const gap = minInterval(provider);
    const last = lastCallAt.get(provider) ?? 0;
    const wait = last + gap - Date.now();
    if (wait > 0) await sleep(wait);
    lastCallAt.set(provider, Date.now());
    return await fn();
  } finally {
    release();
  }
}

export type FetchJsonResult = {
  ok: boolean;
  status: number;
  data: unknown;
  text: string;
};

/**
 * fetch with provider spacing + Retry-After / exponential backoff on 429.
 */
export async function throttledFetchJson(
  provider: ProviderId,
  url: string,
  init?: RequestInit
): Promise<FetchJsonResult> {
  const retries = maxRetries();

  return withProviderThrottle(provider, async () => {
    let attempt = 0;
    for (;;) {
      const res = await fetch(url, {
        ...init,
        headers: {
          Accept: 'application/json',
          ...(init?.headers || {}),
        },
      });
      const text = await res.text();
      let data: unknown = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = { raw: text.slice(0, 800) };
      }

      if (res.status !== 429 || attempt >= retries) {
        return { ok: res.ok, status: res.status, data, text };
      }

      const ra = res.headers.get('retry-after');
      let delayMs = Math.min(30_000, 1000 * Math.pow(2, attempt + 1));
      if (ra) {
        const asNum = Number(ra);
        if (Number.isFinite(asNum)) delayMs = Math.min(60_000, asNum * 1000);
        else {
          const when = Date.parse(ra);
          if (!Number.isNaN(when)) delayMs = Math.min(60_000, Math.max(0, when - Date.now()));
        }
      }
      attempt += 1;
      await sleep(delayMs);
      lastCallAt.set(provider, Date.now());
    }
  });
}

export type { ProviderId };
