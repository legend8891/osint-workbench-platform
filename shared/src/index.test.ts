import { describe, it, expect } from 'vitest';
import {
  promoteConfidence,
  isVerified,
  caseSchema,
  CONFIDENCE_ORDER,
  type CaseRecord,
} from './index';

describe('CONFIDENCE_ORDER', () => {
  it('runs Unverified -> Low -> Medium -> High', () => {
    expect(CONFIDENCE_ORDER).toEqual(['Unverified', 'Low', 'Medium', 'High']);
  });
});

describe('promoteConfidence', () => {
  it('walks one step up the ladder', () => {
    expect(promoteConfidence('Unverified')).toBe('Low');
    expect(promoteConfidence('Low')).toBe('Medium');
    expect(promoteConfidence('Medium')).toBe('High');
  });

  it('caps at High', () => {
    expect(promoteConfidence('High')).toBe('High');
  });

  it('falls back to Low for an unknown value', () => {
    // @ts-expect-error deliberately passing an invalid confidence
    expect(promoteConfidence('bogus')).toBe('Low');
  });
});

describe('isVerified', () => {
  it('is true only when verified === true', () => {
    expect(isVerified({ verified: true })).toBe(true);
    expect(isVerified({ verified: false })).toBe(false);
    expect(isVerified({})).toBe(false);
  });
});

const minimalCase: CaseRecord = {
  id: 'case-1',
  name: 'Test case',
  type: 'person',
  location: '',
  notes: '',
  entities: [],
  relationships: [],
  evidence: [],
  events: [],
  provenance: [],
  report: { summary: '', next: '' },
  createdAt: '2024-01-01T00:00:00.000Z',
};

describe('caseSchema', () => {
  it('accepts a minimal valid case', () => {
    expect(caseSchema.safeParse(minimalCase).success).toBe(true);
  });

  it('accepts optional verification metadata', () => {
    const withVerified = {
      ...minimalCase,
      entities: [
        {
          id: 'e1',
          name: 'Alice',
          type: 'person',
          confidence: 'High',
          identifiers: ['alice@example.com'],
          notes: '',
          verified: true,
          verifiedAt: '2024-02-02T00:00:00.000Z',
          verifiedBy: 'analyst',
        },
      ],
    };
    expect(caseSchema.safeParse(withVerified).success).toBe(true);
  });

  it('rejects a case missing required fields', () => {
    expect(caseSchema.safeParse({ id: 'x' }).success).toBe(false);
  });

  it('rejects an invalid confidence value', () => {
    const bad = {
      ...minimalCase,
      entities: [
        { id: 'e1', name: 'n', type: 't', confidence: 'Nope', identifiers: [], notes: '' },
      ],
    };
    expect(caseSchema.safeParse(bad).success).toBe(false);
  });
});
