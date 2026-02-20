import { safeExternalUrl } from './safeExternalUrl.js';

function asString(value, fallback = '') {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback;
}

function stripHtml(html) {
  return asString(html).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function truncate(text, maxLength = 180) {
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 1).trimEnd()}…`;
}

function normalizeTags(item) {
  if (Array.isArray(item?.categories) && item.categories.length > 0) {
    return item.categories
      .filter((category) => typeof category === 'string' && category.trim().length > 0)
      .slice(0, 3);
  }
  return ['IAM', 'Security'];
}

function deriveRiskLevel(title, summary) {
  const signal = `${title} ${summary}`.toLowerCase();
  if (/(critical|zero-day|rce|exploit|bypass|breach|compromise|active attack|ransomware)/.test(signal)) {
    return 'high';
  }
  if (/(vulnerability|oauth|token|mfa|phishing|credential|advisory)/.test(signal)) {
    return 'medium';
  }
  return 'low';
}

function parsePublishedAt(pubDate) {
  const normalized = asString(pubDate, null);
  if (!normalized) {
    return { pubDate: null, publishedAtMs: null };
  }
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    return { pubDate: null, publishedAtMs: null };
  }
  return { pubDate: parsed.toISOString(), publishedAtMs: parsed.getTime() };
}

export function parseNewsItems(payload, limit = 12) {
  const items = Array.isArray(payload?.items) ? payload.items : [];

  return items
    .slice(0, limit)
    .map((item, index) => {
      const link = safeExternalUrl(item?.link);
      if (!link) {
        return null;
      }

      const title = asString(item?.title, 'Untitled article');
      const summary = truncate(stripHtml(item?.description || item?.content || ''), 220);
      const published = parsePublishedAt(item?.pubDate);

      return {
        id: asString(item?.guid, asString(item?.link, `news-${index}`)),
        title,
        link,
        pubDate: published.pubDate,
        publishedAtMs: published.publishedAtMs,
        source: asString(item?.author || item?.source, 'The Hacker News'),
        summary: summary || 'No summary available.',
        tags: normalizeTags(item),
        riskLevel: deriveRiskLevel(title, summary),
      };
    })
    .filter(Boolean);
}
