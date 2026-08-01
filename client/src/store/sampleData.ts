import type { CaseRecord } from 'shared';

export const sampleCases: CaseRecord[] = [
  {
    id: 'case-1',
    name: 'Alex Morgan Investigation',
    type: 'Person',
    location: 'Melbourne, Victoria, AU',
    notes: 'Primary sample case.',
    entities: [
      {
        id: 'entity-1',
        name: 'Alex Morgan',
        type: 'Person',
        confidence: 'Medium',
        identifiers: ['alexmorgan', 'Melbourne, Victoria, AU'],
        notes: 'Likely person record. Treat as POSSIBLE until further corroboration.',
      },
      {
        id: 'entity-2',
        name: 'alexmorgan.dev',
        type: 'Domain',
        confidence: 'Medium',
        identifiers: ['alexmorgan.dev'],
        notes: 'Observed domain token.',
      },
    ],
    relationships: [
      {
        id: 'rel-1',
        sourceId: 'entity-1',
        targetId: 'entity-2',
        type: 'uses',
        confidence: 'Medium',
        notes: 'Possible personal domain use.',
      },
    ],
    evidence: [
      {
        id: 'ev-1',
        title: 'GitHub handle reused',
        url: 'https://github.com/search?q=alexmorgan',
        archiveUrl: 'https://web.archive.org/',
        confidence: 'Medium',
        entityIds: ['entity-1', 'entity-2'],
        notes: 'Handle overlap. Prefer archive when live page fails.',
        tags: ['github', 'username-reuse'],
        eventDate: '2026-08-02',
        date: '2026-08-02',
        attachments: [],
      },
    ],
    events: [
      {
        id: 'event-1',
        entityId: 'entity-1',
        date: '2026-08-02',
        title: 'Observed GitHub handle reuse',
        notes: 'Consistent naming pattern.',
      },
    ],
    provenance: [
      {
        id: 'prov-1',
        entityId: 'entity-1',
        evidenceId: 'ev-1',
        claim:
          'The GitHub handle may belong to the same individual. Confidence: POSSIBLE / Medium. Needs more corroboration.',
        notes: 'Evidence chain starts at ev-1.',
      },
    ],
    report: {
      summary: 'One possible identity cluster exists around token "alexmorgan".',
      next: 'Check company records, archived domain content, and alternate spellings.',
    },
    createdAt: '2026-08-02T00:00:00.000Z',
  },
  {
    id: 'case-2',
    name: 'Consulting Leads Review',
    type: 'Organisation',
    location: 'Sydney, NSW, AU',
    notes: 'Secondary sample case for reuse detection.',
    entities: [
      {
        id: 'entity-3',
        name: 'alexmorgan',
        type: 'Username',
        confidence: 'Low',
        identifiers: ['alexmorgan'],
        notes: 'Username reused in second case. Treat as POSSIBLE match only.',
      },
    ],
    relationships: [],
    evidence: [],
    events: [],
    provenance: [],
    report: {
      summary: 'Separate case with reused identifier.',
      next: 'Verify whether overlap is genuine or coincidental.',
    },
    createdAt: '2026-08-02T00:10:00.000Z',
  },
];
