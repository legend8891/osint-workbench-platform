import { describe, it, expect } from 'vitest';
import { inferTargetType, FREE_PROVIDER_IDS } from './freerecon.js';

describe('inferTargetType', () => {
  it('detects URLs', () => {
    expect(inferTargetType('https://example.com/path')).toBe('url');
    expect(inferTargetType('http://example.com')).toBe('url');
  });

  it('detects emails', () => {
    expect(inferTargetType('analyst@example.com')).toBe('email');
  });

  it('detects IPv4 addresses', () => {
    expect(inferTargetType('8.8.8.8')).toBe('ip');
    expect(inferTargetType('1.1.1.1')).toBe('ip');
  });

  it('detects domains', () => {
    expect(inferTargetType('example.com')).toBe('domain');
    expect(inferTargetType('sub.example.co.uk')).toBe('domain');
  });

  it('falls back to username for anything else', () => {
    expect(inferTargetType('someusername')).toBe('username');
    expect(inferTargetType('john doe')).toBe('username');
  });
});

describe('FREE_PROVIDER_IDS', () => {
  it('includes the new keyless providers', () => {
    expect(FREE_PROVIDER_IDS).toContain('internetdb');
    expect(FREE_PROVIDER_IDS).toContain('iprdap');
  });

  it('has no duplicate ids', () => {
    expect(new Set(FREE_PROVIDER_IDS).size).toBe(FREE_PROVIDER_IDS.length);
  });
});
