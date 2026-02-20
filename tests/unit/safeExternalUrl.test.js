import test from 'node:test';
import assert from 'node:assert/strict';
import { safeExternalUrl } from '../../src/lib/safeExternalUrl.js';

test('safeExternalUrl accepts https URLs', () => {
  const value = safeExternalUrl('https://example.com/path');
  assert.equal(value, 'https://example.com/path');
});

test('safeExternalUrl rejects javascript protocol', () => {
  const value = safeExternalUrl('javascript:alert(1)');
  assert.equal(value, null);
});

test('safeExternalUrl rejects invalid URL strings', () => {
  const value = safeExternalUrl('not a valid url');
  assert.equal(value, null);
});
