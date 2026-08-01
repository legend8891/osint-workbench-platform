import { z } from 'zod';

export const confidenceSchema = z.enum(['High', 'Medium', 'Low', 'Unverified']);
export type Confidence = z.infer<typeof confidenceSchema>;

export const entitySchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  confidence: confidenceSchema,
  identifiers: z.array(z.string()),
  notes: z.string(),
});
export type EntityRecord = z.infer<typeof entitySchema>;

export const relationshipSchema = z.object({
  id: z.string(),
  sourceId: z.string(),
  targetId: z.string(),
  type: z.string(),
  confidence: confidenceSchema,
  notes: z.string(),
});
export type RelationshipRecord = z.infer<typeof relationshipSchema>;

export const attachmentSchema = z.object({
  name: z.string(),
  type: z.string(),
  dataUrl: z.string(),
});

export const evidenceSchema = z.object({
  id: z.string(),
  title: z.string(),
  url: z.string(),
  archiveUrl: z.string(),
  confidence: confidenceSchema,
  entityIds: z.array(z.string()),
  notes: z.string(),
  tags: z.array(z.string()),
  eventDate: z.string(),
  date: z.string(),
  attachments: z.array(attachmentSchema),
});
export type EvidenceRecord = z.infer<typeof evidenceSchema>;

export const timelineEventSchema = z.object({
  id: z.string(),
  entityId: z.string(),
  date: z.string(),
  title: z.string(),
  notes: z.string(),
});
export type TimelineEvent = z.infer<typeof timelineEventSchema>;

export const provenanceSchema = z.object({
  id: z.string(),
  entityId: z.string(),
  evidenceId: z.string(),
  claim: z.string(),
  notes: z.string(),
});
export type ProvenanceStep = z.infer<typeof provenanceSchema>;

export const caseSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  location: z.string(),
  notes: z.string(),
  entities: z.array(entitySchema),
  relationships: z.array(relationshipSchema),
  evidence: z.array(evidenceSchema),
  events: z.array(timelineEventSchema),
  provenance: z.array(provenanceSchema),
  report: z.object({
    summary: z.string(),
    next: z.string(),
  }),
  createdAt: z.string(),
});
export type CaseRecord = z.infer<typeof caseSchema>;

export type CorrelationMatch = {
  caseId: string;
  caseName: string;
  entityId: string;
  entityName: string;
  entityType: string;
};

export type CorrelationHit = {
  token: string;
  matches: CorrelationMatch[];
};
