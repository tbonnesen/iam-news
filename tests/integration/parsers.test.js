import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNewsItems } from '../../src/lib/news.js';
import { parseNvdVulnerabilities } from '../../src/lib/nvd.js';

test('parseNewsItems keeps only safe links and normalizes fields', () => {
  const payload = {
    items: [
      {
        guid: 'g1',
        title: 'Title One',
        link: 'https://example.com/news/1',
        pubDate: '2026-02-20T10:00:00Z',
        author: 'Example Source',
      },
      {
        guid: 'g2',
        title: 'Bad Link',
        link: 'javascript:alert(1)',
      },
    ],
  };

  const parsed = parseNewsItems(payload, 10);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].id, 'g1');
  assert.equal(parsed[0].title, 'Title One');
  assert.equal(parsed[0].source, 'Example Source');
});

test('parseNvdVulnerabilities maps CVE payload into dashboard schema', () => {
  const payload = {
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2026-0001',
          descriptions: [{ lang: 'en', value: 'Test vulnerability' }],
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }],
          },
        },
      },
    ],
  };

  const parsed = parseNvdVulnerabilities(payload, 10);
  assert.equal(parsed.length, 1);
  assert.deepEqual(parsed[0], {
    title: 'CVE-2026-0001',
    desc: 'Test vulnerability',
    severity: 'critical',
    score: 9.8,
    type: 'CVE Record',
  });
});
