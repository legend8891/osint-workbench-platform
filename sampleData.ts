import type { CaseRecord } from 'shared';

/** App starts with no cases and no synthetic entities. */
export const sampleCases: CaseRecord[] = [];

export function createEmptyCase(name = 'New investigation'): CaseRecord {
  return {
    id: `case-${Date.now()}`,
    name,
    type: 'Investigation',
    location: '',
    notes: '',
    entities: [],
    relationships: [],
    evidence: [],
    events: [],
    provenance: [],
    report: {
      summary: 'No live lookups yet.',
      next: 'Run username, email, domain, or IP lookups from the Lookup tab.',
    },
    createdAt: new Date().toISOString(),
  };
}
