import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8081),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(120),
  RATE_LIMIT_WINDOW: z.string().default('1 minute'),
  UPSTREAM_TIMEOUT_MS: z.coerce.number().int().min(100).default(5000),
  UPSTREAM_RETRIES: z.coerce.number().int().min(0).max(5).default(2),
  CACHE_TTL_MS: z.coerce.number().int().min(1000).default(300000),
  VETTED_NEWS_HOSTS: z.string().default('thehackernews.com,*.thehackernews.com'),
  JWT_ISSUER: z.string().default('iam-news'),
  JWT_AUDIENCE: z.string().default('iam-news-api'),
  JWT_HS256_SECRET: z.string().min(32).default('local-dev-change-me-to-a-long-random-secret')
});

export type AppConfig = {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';
  corsOrigins: string[];
  rateLimitMax: number;
  rateLimitWindow: string;
  upstreamTimeoutMs: number;
  upstreamRetries: number;
  cacheTtlMs: number;
  vettedNewsHosts: string[];
  jwtIssuer: string;
  jwtAudience: string;
  jwtSecret: string;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.parse(env);
  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    logLevel: parsed.LOG_LEVEL,
    corsOrigins: parsed.CORS_ORIGINS.split(',').map((value) => value.trim()).filter(Boolean),
    rateLimitMax: parsed.RATE_LIMIT_MAX,
    rateLimitWindow: parsed.RATE_LIMIT_WINDOW,
    upstreamTimeoutMs: parsed.UPSTREAM_TIMEOUT_MS,
    upstreamRetries: parsed.UPSTREAM_RETRIES,
    cacheTtlMs: parsed.CACHE_TTL_MS,
    vettedNewsHosts: parsed.VETTED_NEWS_HOSTS.split(',').map((value) => value.trim().toLowerCase()).filter(Boolean),
    jwtIssuer: parsed.JWT_ISSUER,
    jwtAudience: parsed.JWT_AUDIENCE,
    jwtSecret: parsed.JWT_HS256_SECRET
  };
}
