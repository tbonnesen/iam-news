function normalizeSeverity(severity) {
  const value = String(severity || 'high').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(value) ? value : 'high';
}

export function parseNvdVulnerabilities(payload, limit = 4) {
  const vulnerabilities = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];

  return vulnerabilities.slice(0, limit).map((entry) => {
    const cve = entry?.cve || {};
    const metrics =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV2?.[0]?.cvssData ||
      null;

    const englishDescription =
      cve.descriptions?.find((description) => description?.lang === 'en')?.value ||
      'No description available';

    return {
      title: cve.id || 'Unknown CVE',
      desc: englishDescription,
      severity: normalizeSeverity(metrics?.baseSeverity),
      score: metrics?.baseScore ?? 'N/A',
      type: 'CVE Record',
    };
  });
}
