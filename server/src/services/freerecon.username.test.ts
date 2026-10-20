import { describe, expect, it, vi } from 'vitest';

vi.mock('./sherlock.js', () => ({
  scanUsername: vi.fn(async (username: string) => ({
    username,
    mode: 'node-fallback' as const,
    hits: [
      {
        site: 'GitHub',
        url: `https://github.com/${username}`,
        status: 'found' as const,
        httpStatus: 200,
        source: 'node-fallback' as const,
      },
    ],
    entities: [
      {
        id: 'entity-test',
        name: username,
        type: 'Username',
        confidence: 'Low' as const,
        identifiers: [username],
        notes: 'test',
      },
    ],
    evidence: [],
    provenance: [],
    notes: [],
  })),
}));

import { runFreeRecon } from './freerecon.js';

describe('runFreeRecon username routing', () => {
  it('runs Sherlock for a bare username instead of returning no providers', async () => {
    const response = await runFreeRecon('octocat');
    expect(response.queryType).toBe('username');
    expect(response.results).toHaveLength(1);
    expect(response.results[0].provider).toBe('sherlock');
    expect(response.results[0].hits[0].url).toBe('https://github.com/octocat');
  });
});
