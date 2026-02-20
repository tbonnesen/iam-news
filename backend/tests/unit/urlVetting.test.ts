import test from 'node:test';
import assert from 'node:assert/strict';
import { vetExternalUrl } from '../../src/security/urlVetting.js';

const vettedHosts = ['thehackernews.com', '*.thehackernews.com', 'nvd.nist.gov'];

test('accepts https URL on vetted host', () => {
  const result = vetExternalUrl('https://thehackernews.com/2026/02/example.html', vettedHosts);
  assert.equal(result.ok, true);
});

test('accepts wildcard subdomain match on vetted host', () => {
  const result = vetExternalUrl('https://blog.thehackernews.com/post', vettedHosts);
  assert.equal(result.ok, true);
});

test('rejects non-https protocol', () => {
  const result = vetExternalUrl('http://thehackernews.com/post', vettedHosts);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'unsupported-protocol');
  }
});

test('rejects unvetted external host', () => {
  const result = vetExternalUrl('https://evil.example.com/dropper', vettedHosts);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'unvetted-host');
  }
});

test('rejects localhost/private network target', () => {
  const localhostResult = vetExternalUrl('https://localhost/internal', vettedHosts);
  assert.equal(localhostResult.ok, false);
  if (!localhostResult.ok) {
    assert.equal(localhostResult.reason, 'private-network-target');
  }

  const privateIpResult = vetExternalUrl('https://192.168.1.10/admin', vettedHosts);
  assert.equal(privateIpResult.ok, false);
  if (!privateIpResult.ok) {
    assert.equal(privateIpResult.reason, 'private-network-target');
  }
});
