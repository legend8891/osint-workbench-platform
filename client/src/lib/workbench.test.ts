import { describe, it, expect } from 'vitest';
import type { CaseRecord, CorrelationHit, EntityRecord } from 'shared';
import {
  sanitizeFilename,
  buildCorrelationHits,
  buildGraphML,
  mergeProviderIntoCase,
  parseImportedCase,
  withUniqueId,
  renameCase,
  deleteCase,
  addRelationship,
  removeRelationship,
  promoteEntityConfidence,
  verifyEntity,
  unverifyEntity,
  type ProviderLookupResult,
} from './workbench';

function makeCase(overrides: Partial<CaseRecord> = {}): CaseRecord {
  return {
    id: 'case-1',
    name: 'Case One',
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
    ...overrides,
  };
}

function makeEntity(overrides: Partial<EntityRecord> = {}): EntityRecord {
  return {
    id: 'ent-1',
    name: 'example.com',
    type: 'domain',
    confidence: 'Low',
    identifiers: ['example.com'],
    notes: '',
    ...overrides,
  };
}

function makeResult(overrides: Partial<ProviderLookupResult> = {}): ProviderLookupResult {
  return {
    provider: 'dns',
    query: 'example.com',
    ok: true,
    hits: [],
    entities: [],
    evidence: [],
    provenance: [],
    ...overrides,
  };
}

describe('sanitizeFilename', () => {
  it('leaves safe names untouched', () => {
    expect(sanitizeFilename('normal-name.txt')).toBe('normal-name.txt');
  });

  it('replaces path separators and unsafe characters', () => {
    expect(sanitizeFilename('a/b\\c')).toBe('a_b_c');
    expect(sanitizeFilename('a<b>c:d')).toBe('a_b_c_d');
  });

  it('falls back to "case" for empty / whitespace-only names', () => {
    expect(sanitizeFilename('')).toBe('case');
    expect(sanitizeFilename('   ')).toBe('case');
    // A run of unsafe characters collapses to a single underscore (still a valid name).
    expect(sanitizeFilename('///')).toBe('_');
  });
});

describe('buildCorrelationHits', () => {
  it('flags identifiers shared across two cases', () => {
    const a = makeCase({
      id: 'a',
      name: 'A',
      entities: [makeEntity({ id: 'a1', identifiers: ['shared@example.com'] })],
    });
    const b = makeCase({
      id: 'b',
      name: 'B',
      entities: [makeEntity({ id: 'b1', identifiers: ['Shared@Example.com'] })],
    });
    const hits = buildCorrelationHits([a, b]);
    expect(hits).toHaveLength(1);
    expect(hits[0].token).toBe('shared@example.com');
    expect(hits[0].matches).toHaveLength(2);
  });

  it('ignores identifiers confined to a single case', () => {
    const a = makeCase({
      id: 'a',
      entities: [makeEntity({ id: 'a1', identifiers: ['only@example.com'] })],
    });
    expect(buildCorrelationHits([a])).toHaveLength(0);
  });
});

describe('mergeProviderIntoCase', () => {
  it('de-duplicates entities by type+name and unions identifiers', () => {
    const record = makeCase({ entities: [makeEntity({ id: 'old', identifiers: ['example.com'] })] });
    const result = makeResult({
      entities: [makeEntity({ id: 'new', identifiers: ['example.com', '1.2.3.4'] })],
    });
    const merged = mergeProviderIntoCase(record, [result]);
    expect(merged.entities).toHaveLength(1);
    expect(merged.entities[0].identifiers).toEqual(['example.com', '1.2.3.4']);
  });

  it('never downgrades an analyst-verified entity', () => {
    const record = makeCase({
      entities: [makeEntity({ id: 'old', confidence: 'High', verified: true, verifiedBy: 'analyst' })],
    });
    const result = makeResult({ entities: [makeEntity({ id: 'new', confidence: 'Low' })] });
    const merged = mergeProviderIntoCase(record, [result]);
    expect(merged.entities[0].verified).toBe(true);
    expect(merged.entities[0].confidence).toBe('High');
    expect(merged.entities[0].verifiedBy).toBe('analyst');
  });

  it('skips failed provider results', () => {
    const merged = mergeProviderIntoCase(makeCase(), [
      makeResult({ ok: false, error: 'boom', entities: [makeEntity()] }),
    ]);
    expect(merged.entities).toHaveLength(0);
    expect(merged.events).toHaveLength(0);
  });

  it('appends a timeline event for each successful provider', () => {
    const merged = mergeProviderIntoCase(makeCase(), [makeResult()]);
    expect(merged.events).toHaveLength(1);
    expect(merged.events[0].title).toContain('dns');
  });
});

describe('buildGraphML', () => {
  it('emits a correlation data key and per-node correlation values', () => {
    const record = makeCase({ entities: [makeEntity({ id: 'e1' })] });
    const hits: CorrelationHit[] = [
      {
        token: 'shared-token',
        matches: [
          { caseId: 'case-1', caseName: 'Case One', entityId: 'e1', entityName: 'example.com', entityType: 'domain' },
          { caseId: 'case-2', caseName: 'Case Two', entityId: 'x', entityName: 'example.com', entityType: 'domain' },
        ],
      },
    ];
    const xml = buildGraphML(record, hits);
    expect(xml).toContain('<key id="correlation"');
    expect(xml).toContain('<data key="correlation">shared-token</data>');
  });

  it('omits correlation data when there are no hits for the case', () => {
    const xml = buildGraphML(makeCase({ entities: [makeEntity({ id: 'e1' })] }), []);
    expect(xml).not.toContain('<data key="correlation">');
  });
});

describe('parseImportedCase / withUniqueId', () => {
  it('parses a valid exported case', () => {
    const record = makeCase();
    const parsed = parseImportedCase(JSON.stringify(record));
    expect(parsed.id).toBe('case-1');
    expect(parsed.name).toBe('Case One');
  });

  it('throws a readable error for invalid JSON', () => {
    expect(() => parseImportedCase('{not json')).toThrow(/Not valid JSON/);
  });

  it('throws a readable error for JSON that is not a valid case', () => {
    expect(() => parseImportedCase(JSON.stringify({ id: 'x' }))).toThrow(/Invalid case file/);
  });

  it('keeps the id when it is unique', () => {
    const record = makeCase({ id: 'unique' });
    expect(withUniqueId(record, [makeCase({ id: 'other' })]).id).toBe('unique');
  });

  it('re-ids a record whose id already exists', () => {
    const record = makeCase({ id: 'dup' });
    const result = withUniqueId(record, [makeCase({ id: 'dup' })]);
    expect(result.id).not.toBe('dup');
    expect(result.id.startsWith('dup-')).toBe(true);
  });
});

describe('case mutations', () => {
  it('renames a case', () => {
    const next = renameCase([makeCase()], 'case-1', 'Renamed');
    expect(next[0].name).toBe('Renamed');
  });

  it('deletes a case', () => {
    expect(deleteCase([makeCase()], 'case-1')).toHaveLength(0);
  });

  it('adds and removes a relationship', () => {
    const withRel = addRelationship(makeCase(), 'a', 'b', 'knows');
    expect(withRel.relationships).toHaveLength(1);
    const removed = removeRelationship(withRel, withRel.relationships[0].id);
    expect(removed.relationships).toHaveLength(0);
  });

  it('refuses self-referential relationships', () => {
    expect(addRelationship(makeCase(), 'a', 'a', 'self').relationships).toHaveLength(0);
  });
});

describe('verification workflow', () => {
  it('promoting confidence clears verification metadata', () => {
    const record = makeCase({
      entities: [makeEntity({ id: 'e1', verified: true, verifiedAt: 'x', verifiedBy: 'analyst' })],
    });
    const next = promoteEntityConfidence(record, 'e1');
    expect(next.entities[0].verified).toBe(false);
    expect(next.entities[0].verifiedAt).toBeUndefined();
    expect(next.entities[0].verifiedBy).toBeUndefined();
  });

  it('verifying sets High confidence and appends provenance', () => {
    const record = makeCase({ entities: [makeEntity({ id: 'e1' })] });
    const next = verifyEntity(record, 'e1');
    expect(next.entities[0].verified).toBe(true);
    expect(next.entities[0].confidence).toBe('High');
    expect(next.provenance).toHaveLength(1);
  });

  it('re-verifying is idempotent (no duplicate provenance)', () => {
    const record = makeCase({ entities: [makeEntity({ id: 'e1' })] });
    const once = verifyEntity(record, 'e1');
    const twice = verifyEntity(once, 'e1');
    expect(twice.provenance).toHaveLength(1);
  });

  it('unverifying drops back to Medium and clears metadata', () => {
    const record = makeCase({
      entities: [makeEntity({ id: 'e1', verified: true, verifiedAt: 'x', verifiedBy: 'analyst' })],
    });
    const next = unverifyEntity(record, 'e1');
    expect(next.entities[0].verified).toBe(false);
    expect(next.entities[0].confidence).toBe('Medium');
  });
});
