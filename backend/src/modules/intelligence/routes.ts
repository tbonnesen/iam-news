import type { FastifyPluginAsync } from 'fastify';
import type { AppConfig } from '../../config.js';
import { requireRoles } from '../../security/auth.js';
import { briefingQuerySchema, refreshBodySchema } from './schema.js';
import { IntelligenceService } from './service.js';

const idempotencyStore = new Map<string, number>();
const IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;

function cleanupIdempotencyStore(nowMs: number): void {
  for (const [key, timestamp] of idempotencyStore.entries()) {
    if (nowMs - timestamp > IDEMPOTENCY_TTL_MS) {
      idempotencyStore.delete(key);
    }
  }
}

type IntelligencePluginOptions = {
  config: AppConfig;
  intelligenceService: IntelligenceService;
};

const intelligenceRoutes: FastifyPluginAsync<IntelligencePluginOptions> = async (app, options) => {
  app.get('/briefing', async (request, reply) => {
    const parsedQuery = briefingQuerySchema.safeParse(request.query);
    if (!parsedQuery.success) {
      return reply.code(400).send({
        error: 'Invalid query',
        details: parsedQuery.error.flatten()
      });
    }

    const { window, limit } = parsedQuery.data;
    const briefing = await options.intelligenceService.getBriefing(window, limit);

    return reply.code(200).send(briefing);
  });

  app.post(
    '/admin/refresh',
    {
      preHandler: requireRoles(options.config, ['admin'])
    },
    async (request, reply) => {
      const parsedBody = refreshBodySchema.safeParse(request.body || {});
      if (!parsedBody.success) {
        return reply.code(400).send({
          error: 'Invalid body',
          details: parsedBody.error.flatten()
        });
      }

      const idempotencyKey = request.headers['idempotency-key'];
      if (typeof idempotencyKey !== 'string' || idempotencyKey.trim().length < 8) {
        return reply.code(400).send({
          error: 'Missing or invalid idempotency key'
        });
      }

      const nowMs = Date.now();
      cleanupIdempotencyStore(nowMs);

      if (idempotencyStore.has(idempotencyKey)) {
        return reply.code(202).send({
          accepted: true,
          deduplicated: true
        });
      }

      idempotencyStore.set(idempotencyKey, nowMs);
      await options.intelligenceService.refresh(parsedBody.data.window);

      request.log.info(
        {
          actor: request.auth?.sub,
          roles: request.auth?.roles,
          window: parsedBody.data.window || 'all'
        },
        'manual intelligence refresh accepted'
      );

      return reply.code(202).send({
        accepted: true,
        deduplicated: false
      });
    }
  );
};

export default intelligenceRoutes;
