import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { loadConfig, type AppConfig } from './config.js';
import healthRoutes from './modules/health/routes.js';
import intelligenceRoutes from './modules/intelligence/routes.js';
import { IntelligenceService } from './modules/intelligence/service.js';

type BuildAppOptions = {
  config?: AppConfig;
  intelligenceService?: IntelligenceService;
};

export function buildApp(options: BuildAppOptions = {}): FastifyInstance {
  const config = options.config ?? loadConfig();

  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: {
        paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
        censor: '[REDACTED]'
      }
    },
    requestIdHeader: 'x-request-id'
  });

  const intelligenceService =
    options.intelligenceService ?? new IntelligenceService(config, app.log);

  void app.register(helmet, {
    global: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"]
      }
    }
  });

  void app.register(cors, {
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }

      const allowed = config.corsOrigins.includes(origin);
      callback(allowed ? null : new Error('Origin not allowed'), allowed);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key', 'X-Request-Id'],
    credentials: false,
    maxAge: 300
  });

  void app.register(rateLimit, {
    global: true,
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindow,
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true
    }
  });

  void app.register(healthRoutes, { prefix: '/health' });
  void app.register(intelligenceRoutes, {
    prefix: '/api/v1/intelligence',
    config,
    intelligenceService
  });

  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, 'request failed');
    const normalizedError = error as { statusCode?: number; message?: string };

    if (!reply.sent) {
      const statusCode =
        normalizedError.statusCode && normalizedError.statusCode >= 400
          ? normalizedError.statusCode
          : 500;
      void reply.code(statusCode).send({
        error: statusCode >= 500 ? 'Internal Server Error' : normalizedError.message || 'Request failed',
        requestId: request.id
      });
    }
  });

  return app;
}
