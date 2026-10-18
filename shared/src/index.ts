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
  // Analyst verification workflow — a finding is only "verified" once a human
  // explicitly promotes it. Tools never set these.
  verified: z.boolean().optional(),
  verifiedAt: z.string().optional(),
  verifiedBy: z.string().optional(),
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
  verified: z.boolean().optional(),
  verifiedAt: z.string().optional(),
  verifiedBy: z.string().optional(),
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

/** Ordered confidence ladder used by the analyst verification workflow. */
export const CONFIDENCE_ORDER: Confidence[] = ['Unverified', 'Low', 'Medium', 'High'];

/** Promote a confidence value one step up the ladder (capped at High). */
export function promoteConfidence(current: Confidence): Confidence {
  const idx = CONFIDENCE_ORDER.indexOf(current);
  if (idx < 0) return 'Low';
  return CONFIDENCE_ORDER[Math.min(idx + 1, CONFIDENCE_ORDER.length - 1)];
}

/** A record is "verified" only when an analyst explicitly marks it so. */
export function isVerified(record: { verified?: boolean }): boolean {
  return record.verified === true;
}
