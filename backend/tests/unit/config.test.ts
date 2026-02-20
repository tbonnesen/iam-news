import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../../src/config.js';

test('loadConfig parses defaults safely', () => {
  const config = loadConfig({});

  assert.equal(config.port, 8081);
  assert.deepEqual(config.corsOrigins, ['http://localhost:5173']);
  assert.ok(config.jwtSecret.length >= 32);
});

test('loadConfig parses comma separated origins', () => {
  const config = loadConfig({ CORS_ORIGINS: 'https://app.example.com,https://admin.example.com' });
  assert.deepEqual(config.corsOrigins, ['https://app.example.com', 'https://admin.example.com']);
});
