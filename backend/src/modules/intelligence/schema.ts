import { z } from 'zod';

export const briefingQuerySchema = z.object({
  window: z.enum(['24h', '7d']).default('24h'),
  limit: z.coerce.number().int().min(1).max(20).optional()
});

export const refreshBodySchema = z.object({
  window: z.enum(['24h', '7d']).optional()
});
