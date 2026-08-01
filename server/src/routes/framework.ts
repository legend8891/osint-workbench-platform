import { Router } from 'express';
import { z } from 'zod';
import {
  FRAMEWORK_CATEGORIES,
  buildToolUrl,
  getFrameworkCatalog,
} from '../services/framework.js';

export const frameworkRouter = Router();

/** Full OSINT Framework catalog + which API keys are configured on this host. */
frameworkRouter.get('/', (_req, res) => {
  res.json(getFrameworkCatalog());
});

/** Resolve a tool launch URL (optional query string for templates). */
frameworkRouter.get('/launch', (req, res) => {
  const schema = z.object({
    toolId: z.string().min(1),
    q: z.string().optional().default(''),
  });
  const parsed = schema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query', details: parsed.error.flatten() });
    return;
  }

  const { toolId, q } = parsed.data;
  for (const cat of FRAMEWORK_CATEGORIES) {
    const tool = cat.tools.find((t) => t.id === toolId);
    if (tool) {
      res.json({
        toolId: tool.id,
        name: tool.name,
        url: buildToolUrl(tool, q),
        providerId: tool.providerId ?? null,
        opsec: tool.opsec,
        flag: tool.flag,
      });
      return;
    }
  }
  res.status(404).json({ error: 'Tool not found', toolId });
});
