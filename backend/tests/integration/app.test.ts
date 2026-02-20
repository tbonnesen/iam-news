import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/app.js';
import type { IntelligenceBriefing } from '../../src/domain/types.js';
import { loadConfig } from '../../src/config.js';

const baseBriefing: IntelligenceBriefing = {
  generatedAt: '2026-02-20T00:00:00.000Z',
  window: '24h',
  stale: false,
  news: [],
  threats: [],
  vulnerabilities: []
};

let app: FastifyInstance | null = null;

async function cleanup(): Promise<void> {
  if (app) {
    await app.close();
    app = null;
  }
}

test('returns liveness probe', async () => {
  app = buildApp({ config: loadConfig({ NODE_ENV: 'test' }) });

  try {
    const response = await app.inject({ method: 'GET', url: '/health/live' });
    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), { status: 'ok' });
  } finally {
    await cleanup();
  }
});

test('returns intelligence briefing from service', async () => {
  const fakeService = {
    getBriefing: async () => baseBriefing,
    refresh: async () => undefined
  };

  app = buildApp({
    config: loadConfig({ NODE_ENV: 'test' }),
    intelligenceService: fakeService as any
  });

  try {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/intelligence/briefing?window=24h'
    });

    assert.equal(response.statusCode, 200);
    assert.equal(response.json().window, '24h');
  } finally {
    await cleanup();
  }
});

test('enforces admin auth and idempotency on refresh endpoint', async () => {
  const fakeService = {
    getBriefing: async () => baseBriefing,
    refresh: async () => undefined
  };

  const config = loadConfig({ NODE_ENV: 'test', JWT_HS256_SECRET: 'test-secret-which-is-at-least-32-chars' });

  app = buildApp({
    config,
    intelligenceService: fakeService as any
  });

  try {
    const unauthenticated = await app.inject({
      method: 'POST',
      url: '/api/v1/intelligence/admin/refresh',
      headers: { 'idempotency-key': 'abcdefghi' },
      payload: { window: '24h' }
    });

    assert.equal(unauthenticated.statusCode, 401);

    const token = await new SignJWT({ roles: ['admin'] })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setIssuer(config.jwtIssuer)
      .setAudience(config.jwtAudience)
      .setSubject('test-user')
      .setExpirationTime('10m')
      .sign(new TextEncoder().encode(config.jwtSecret));

    const first = await app.inject({
      method: 'POST',
      url: '/api/v1/intelligence/admin/refresh',
      headers: {
        authorization: `Bearer ${token}`,
        'idempotency-key': 'abcdefghi'
      },
      payload: { window: '24h' }
    });

    assert.equal(first.statusCode, 202);
    assert.equal(first.json().accepted, true);
    assert.equal(first.json().deduplicated, false);

    const second = await app.inject({
      method: 'POST',
      url: '/api/v1/intelligence/admin/refresh',
      headers: {
        authorization: `Bearer ${token}`,
        'idempotency-key': 'abcdefghi'
      },
      payload: { window: '24h' }
    });

    assert.equal(second.statusCode, 202);
    assert.equal(second.json().accepted, true);
    assert.equal(second.json().deduplicated, true);
  } finally {
    await cleanup();
  }
});
