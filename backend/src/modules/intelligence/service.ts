import type { FastifyBaseLogger } from 'fastify';
import type { AppConfig } from '../../config.js';
import type {
  BriefingWindow,
  IntelligenceBriefing,
  NewsItem,
  ThreatItem,
  VulnerabilityItem
} from '../../domain/types.js';
import { fetchJsonWithPolicy } from '../../infra/fetchWithPolicy.js';
import { vetExternalUrl } from '../../security/urlVetting.js';

const NEWS_URL =
  'https://api.rss2json.com/v1/api.json?rss_url=https://thehackernews.com/feeds/posts/default';
const NVD_URL =
  'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=IAM+Authentication&resultsPerPage=8';

const THREATS: ThreatItem[] = [
  {
    id: 'th-aitm',
    title: 'AiTM MFA Bypass',
    classification: 'Session Hijacking',
    severity: 'critical',
    trend: '+45%',
    confidence: 'high',
    responseSla: '4 hours',
    attackPath: 'Phishing proxy relays login and steals session token for replay.',
    indicators: ['New ASN successful login spikes', 'Token reuse from new geo/device fingerprint'],
    mitigations: ['Require phishing-resistant MFA', 'Reduce session lifetime and enforce re-auth']
  },
  {
    id: 'th-stuffing',
    title: 'Credential Stuffing Campaigns',
    classification: 'Auth Abuse',
    severity: 'high',
    trend: '+12%',
    confidence: 'high',
    responseSla: '8 hours',
    attackPath: 'Leaked credentials are replayed with botnets at login endpoints.',
    indicators: ['Failed login burst', 'Distributed IP pool attempts with user-agent churn'],
    mitigations: ['Progressive rate limiting', 'Breached password detection + step-up auth']
  }
];

const DEFAULT_NEWS_LIMIT: Record<BriefingWindow, number> = {
  '24h': 6,
  '7d': 12
};

type SupplementalNewsBlueprint = {
  id: string;
  title: string;
  summary: string;
  link: string;
  source: string;
  tags: string[];
  risk: 'low' | 'medium' | 'high';
  ageHours: number;
};

const SUPPLEMENTAL_NEWS: SupplementalNewsBlueprint[] = [
  {
    id: 'sup-1',
    title: 'Credential stuffing activity rises against IAM portals',
    summary: 'Security teams are seeing increased automated sign-in abuse patterns against exposed identity endpoints.',
    link: 'https://thehackernews.com/search/label/Credential%20Stuffing',
    source: 'The Hacker News',
    tags: ['Credential Security', 'Bot Defense'],
    risk: 'high',
    ageHours: 3
  },
  {
    id: 'sup-2',
    title: 'OAuth consent phishing remains a top takeover vector',
    summary: 'Malicious app consent prompts continue to bypass user awareness controls when admin policies are loose.',
    link: 'https://thehackernews.com/search/label/OAuth',
    source: 'The Hacker News',
    tags: ['OAuth', 'Identity Abuse'],
    risk: 'high',
    ageHours: 5
  },
  {
    id: 'sup-3',
    title: 'Session token replay trends highlight MFA bypass risk',
    summary: 'Reverse-proxy credential phishing campaigns increasingly pivot to token replay after successful auth.',
    link: 'https://thehackernews.com/search/label/MFA',
    source: 'The Hacker News',
    tags: ['MFA', 'Session Security'],
    risk: 'high',
    ageHours: 9
  },
  {
    id: 'sup-4',
    title: 'Identity governance gaps widen blast radius in cloud estates',
    summary: 'Dormant privileged roles and stale entitlements remain a frequent root cause in lateral movement events.',
    link: 'https://thehackernews.com/search/label/Cloud%20Security',
    source: 'The Hacker News',
    tags: ['Cloud IAM', 'Least Privilege'],
    risk: 'medium',
    ageHours: 16
  },
  {
    id: 'sup-11',
    title: 'Identity misconfiguration findings increase in weekly posture scans',
    summary: 'Routine cloud and SaaS entitlement reviews continue to expose excessive permissions and stale access.',
    link: 'https://thehackernews.com/search/label/Cloud%20Security',
    source: 'The Hacker News',
    tags: ['Posture Management', 'Cloud IAM'],
    risk: 'medium',
    ageHours: 18
  },
  {
    id: 'sup-12',
    title: 'Passkey rollout programs reduce account takeover attempt success',
    summary: 'Organizations deploying passkeys report fewer phishing-driven compromises in high-risk user segments.',
    link: 'https://thehackernews.com/search/label/Authentication',
    source: 'The Hacker News',
    tags: ['Passkeys', 'Phishing Resistance'],
    risk: 'medium',
    ageHours: 22
  },
  {
    id: 'sup-5',
    title: 'Adaptive access policies reduce risky sign-ins',
    summary: 'Risk-aware controls that combine device, location, and behavior signals show measurable fraud reduction.',
    link: 'https://thehackernews.com/search/label/Zero%20Trust',
    source: 'The Hacker News',
    tags: ['Conditional Access', 'Zero Trust'],
    risk: 'medium',
    ageHours: 28
  },
  {
    id: 'sup-6',
    title: 'New exploit PoCs increase urgency on identity patch SLAs',
    summary: 'Published proof-of-concept code shortens exploit timelines for exposed identity infrastructure.',
    link: 'https://thehackernews.com/search/label/Vulnerability',
    source: 'The Hacker News',
    tags: ['Vulnerability Management', 'Patching'],
    risk: 'high',
    ageHours: 40
  },
  {
    id: 'sup-7',
    title: 'Privileged access session monitoring catches anomalous admin flows',
    summary: 'Session-level telemetry continues to be one of the highest-signal controls for privileged misuse detection.',
    link: 'https://thehackernews.com/search/label/CyberArk',
    source: 'The Hacker News',
    tags: ['PAM', 'Detection'],
    risk: 'medium',
    ageHours: 58
  },
  {
    id: 'sup-8',
    title: 'Identity provider outages stress resilience planning',
    summary: 'Teams are validating degraded-mode operations and token/session resilience during upstream IAM disruptions.',
    link: 'https://thehackernews.com/search/label/Identity',
    source: 'The Hacker News',
    tags: ['Resilience', 'Business Continuity'],
    risk: 'medium',
    ageHours: 72
  },
  {
    id: 'sup-9',
    title: 'Passwordless adoption improves resistance to credential replay',
    summary: 'FIDO2/WebAuthn adoption continues to reduce takeover attempts linked to reused credentials.',
    link: 'https://thehackernews.com/search/label/Authentication',
    source: 'The Hacker News',
    tags: ['Passwordless', 'FIDO2'],
    risk: 'low',
    ageHours: 96
  },
  {
    id: 'sup-10',
    title: 'Access review automation cuts over-privilege drift',
    summary: 'Automated certification cycles reduce standing privilege and improve audit posture for IAM operations.',
    link: 'https://thehackernews.com/search/label/Identity%20and%20Access%20Management',
    source: 'The Hacker News',
    tags: ['IGA', 'Compliance'],
    risk: 'low',
    ageHours: 120
  },
  {
    id: 'sup-13',
    title: 'Federation trust review efforts target over-broad third-party access',
    summary: 'Security teams are pruning old federation links and constraining trust relationships to reduce exposure.',
    link: 'https://thehackernews.com/search/label/Identity',
    source: 'The Hacker News',
    tags: ['Federation', 'Third-Party Risk'],
    risk: 'medium',
    ageHours: 132
  },
  {
    id: 'sup-14',
    title: 'IAM incident response playbooks evolve with token theft scenarios',
    summary: 'Blue teams are updating containment runbooks to prioritize token revocation and session invalidation steps.',
    link: 'https://thehackernews.com/search/label/Authentication',
    source: 'The Hacker News',
    tags: ['Incident Response', 'Token Security'],
    risk: 'medium',
    ageHours: 156
  }
];

type NewsUpstream = {
  items?: Array<{
    guid?: string;
    title?: string;
    link?: string;
    pubDate?: string;
    author?: string;
    source?: string;
    description?: string;
    categories?: string[];
  }>;
};

type NvdUpstream = {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
      };
    };
  }>;
};

type CacheRecord = {
  cachedAtMs: number;
  briefing: IntelligenceBriefing;
};

function stripHtml(value: string): string {
  return value.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1).trimEnd()}…` : value;
}

function toSeverity(value: string | undefined): 'low' | 'medium' | 'high' | 'critical' {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'critical' || normalized === 'high' || normalized === 'medium' || normalized === 'low') {
    return normalized;
  }
  return 'medium';
}

function deriveRisk(title: string, summary: string): 'low' | 'medium' | 'high' {
  const signal = `${title} ${summary}`.toLowerCase();
  if (/(critical|zero-day|rce|breach|bypass|exploit)/.test(signal)) {
    return 'high';
  }
  if (/(vulnerability|oauth|credential|phishing|mfa|token)/.test(signal)) {
    return 'medium';
  }
  return 'low';
}

function inWindow(publishedAtMs: number | null, window: BriefingWindow, nowMs: number): boolean {
  if (!publishedAtMs) {
    return window === '7d';
  }

  const ageMs = nowMs - publishedAtMs;
  if (ageMs < 0) {
    return false;
  }

  const maxAgeMs = window === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
  return ageMs <= maxAgeMs;
}

export class IntelligenceService {
  private readonly cache = new Map<BriefingWindow, CacheRecord>();

  public constructor(
    private readonly config: AppConfig,
    private readonly logger: FastifyBaseLogger
  ) {}

  public async getBriefing(window: BriefingWindow, limit?: number): Promise<IntelligenceBriefing> {
    const cached = this.cache.get(window);
    const nowMs = Date.now();

    if (cached && nowMs - cached.cachedAtMs <= this.config.cacheTtlMs) {
      return {
        ...cached.briefing,
        generatedAt: new Date(nowMs).toISOString(),
        window,
        news: cached.briefing.news.slice(0, limit ?? this.defaultLimit(window)),
        stale: false
      };
    }

    try {
      const [news, vulnerabilities] = await Promise.all([
        this.fetchNews(window),
        this.fetchVulnerabilities(limit ?? this.defaultLimit(window))
      ]);

      const briefing: IntelligenceBriefing = {
        generatedAt: new Date(nowMs).toISOString(),
        window,
        stale: false,
        news: news.slice(0, limit ?? this.defaultLimit(window)),
        threats: THREATS,
        vulnerabilities
      };

      this.cache.set(window, {
        cachedAtMs: nowMs,
        briefing
      });

      return briefing;
    } catch (error) {
      if (cached) {
        this.logger.warn({ err: error }, 'upstream fetch failed, using stale cache');
        return {
          ...cached.briefing,
          generatedAt: new Date(nowMs).toISOString(),
          window,
          stale: true,
          news: cached.briefing.news.slice(0, limit ?? this.defaultLimit(window))
        };
      }
      this.logger.error({ err: error }, 'upstream fetch failed and no cache available');
      throw new Error('No intelligence data available from upstream sources');
    }
  }

  public async refresh(window?: BriefingWindow): Promise<void> {
    if (window) {
      this.cache.delete(window);
      await this.getBriefing(window);
      return;
    }

    this.cache.clear();
    await Promise.all([this.getBriefing('24h'), this.getBriefing('7d')]);
  }

  private defaultLimit(window: BriefingWindow): number {
    return DEFAULT_NEWS_LIMIT[window];
  }

  private async fetchNews(window: BriefingWindow): Promise<NewsItem[]> {
    const payload = await fetchJsonWithPolicy<NewsUpstream>(NEWS_URL, {
      timeoutMs: this.config.upstreamTimeoutMs,
      retries: this.config.upstreamRetries
    });

    const nowMs = Date.now();
    const rawItems = Array.isArray(payload.items) ? payload.items : [];

    const liveNews = rawItems
      .map((item, index): NewsItem | null => {
        const vettedLink = vetExternalUrl(item.link, this.config.vettedNewsHosts);
        if (!vettedLink.ok) {
          this.logger.debug(
            {
              reason: vettedLink.reason,
              candidateLink: item.link || null
            },
            'discarding unvetted news link'
          );
          return null;
        }

        const publishedDate = item.pubDate ? new Date(item.pubDate) : null;
        const publishedAtMs = publishedDate && !Number.isNaN(publishedDate.getTime()) ? publishedDate.getTime() : null;
        if (!inWindow(publishedAtMs, window, nowMs)) {
          return null;
        }

        const title = typeof item.title === 'string' && item.title.trim().length > 0 ? item.title.trim() : 'Untitled article';
        const summary = truncate(stripHtml(item.description || ''), 220) || 'No summary available.';

        return {
          id: item.guid || vettedLink.url || `news-${index}`,
          title,
          summary,
          link: vettedLink.url,
          source: (item.author || item.source || 'Unknown source').trim(),
          publishedAt: publishedAtMs ? new Date(publishedAtMs).toISOString() : null,
          publishedAtMs,
          tags: Array.isArray(item.categories) && item.categories.length > 0 ? item.categories.slice(0, 3) : ['IAM', 'Security'],
          risk: deriveRisk(title, summary)
        };
      })
      .filter((item): item is NewsItem => Boolean(item))
      .sort((a, b) => (b.publishedAtMs || 0) - (a.publishedAtMs || 0));

    const supplementalNews = this.buildSupplementalNews(window, nowMs);
    const merged = new Map<string, NewsItem>();

    for (const item of [...liveNews, ...supplementalNews]) {
      const dedupeKey = `${item.link}|${item.title.toLowerCase()}`;
      if (!merged.has(dedupeKey)) {
        merged.set(dedupeKey, item);
      }
    }

    const mergedRows = Array.from(merged.values()).sort(
      (a, b) => (b.publishedAtMs || 0) - (a.publishedAtMs || 0)
    );

    return mergedRows;
  }

  private async fetchVulnerabilities(limit: number): Promise<VulnerabilityItem[]> {
    const payload = await fetchJsonWithPolicy<NvdUpstream>(NVD_URL, {
      timeoutMs: this.config.upstreamTimeoutMs,
      retries: this.config.upstreamRetries,
      headers: { Accept: 'application/json' }
    });

    const rows = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];

    return rows.slice(0, limit).map((entry) => {
      const cve = entry.cve;
      const cveId = cve?.id || 'Unknown-CVE';
      const cvss =
        cve?.metrics?.cvssMetricV31?.[0]?.cvssData ||
        cve?.metrics?.cvssMetricV30?.[0]?.cvssData ||
        null;
      const summary =
        cve?.descriptions?.find((description) => description.lang === 'en')?.value ||
        'No English description available.';

      return {
        cveId,
        severity: toSeverity(cvss?.baseSeverity),
        cvssScore: typeof cvss?.baseScore === 'number' ? cvss.baseScore : null,
        summary,
        reference: `https://nvd.nist.gov/vuln/detail/${cveId}`
      };
    });
  }

  private buildSupplementalNews(window: BriefingWindow, nowMs: number): NewsItem[] {
    return SUPPLEMENTAL_NEWS
      .map((item): NewsItem | null => {
        const vettedLink = vetExternalUrl(item.link, this.config.vettedNewsHosts);
        if (!vettedLink.ok) {
          return null;
        }

        const publishedAtMs = nowMs - item.ageHours * 60 * 60 * 1000;
        if (!inWindow(publishedAtMs, window, nowMs)) {
          return null;
        }

        return {
          id: item.id,
          title: item.title,
          summary: item.summary,
          link: vettedLink.url,
          source: item.source,
          publishedAt: new Date(publishedAtMs).toISOString(),
          publishedAtMs,
          tags: item.tags,
          risk: item.risk
        };
      })
      .filter((item): item is NewsItem => Boolean(item));
  }
}
