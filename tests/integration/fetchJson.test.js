import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchJson } from '../../src/lib/fetchJson.js';

test('fetchJson retries and eventually returns payload', async () => {
  const originalFetch = globalThis.fetch;
  let attempts = 0;

  globalThis.fetch = async () => {
    attempts += 1;
    if (attempts < 2) {
      throw new Error('temporary failure');
    }
    return {
      ok: true,
      json: async () => ({ ok: true, attempts }),
    };
  };

  try {
    const data = await fetchJson('https://example.com', { retries: 1, retryDelayMs: 1 });
    assert.equal(data.ok, true);
    assert.equal(data.attempts, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchJson throws on non-2xx response', async () => {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () => ({
    ok: false,
    status: 503,
    json: async () => ({}),
  });

  try {
    await assert.rejects(
      fetchJson('https://example.com', { retries: 0 }),
      /HTTP 503/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
