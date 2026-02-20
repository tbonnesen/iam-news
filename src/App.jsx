import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  RefreshCw,
  Newspaper,
  Wrench,
  Activity,
  ShieldBan,
  Download,
  ExternalLink,
  ShieldCheck,
  KeyRound,
  Shield,
  ShieldAlert,
  Users,
} from 'lucide-react';
import { toCsv } from './lib/csv';
import { fetchJson } from './lib/fetchJson';

// Augmented Static Data for Tools & Threats with drill-down metadata
const topTools = [
  {
    id: 't1',
    name: 'Okta / Auth0',
    desc: 'Market leader in access management and CIAM.',
    metric: '42% Market Share',
    category: 'CIAM + Workforce IAM',
    longDesc: 'Unified identity platform for customer and workforce access with mature federation and lifecycle tooling.',
    bestFor: 'Enterprises standardizing SSO and adaptive MFA across SaaS and custom apps.',
    pricingModel: 'Per active user / monthly active user tiers',
    strengths: ['Large integration catalog', 'Mature policy engine', 'Reliable global footprint'],
    watchouts: ['Can become expensive at scale', 'Complex policy sprawl without governance'],
    integrationHighlights: ['SCIM provisioning', 'SAML/OIDC federation', 'Risk-based MFA'],
    icon: ShieldCheck,
  },
  {
    id: 't2',
    name: 'Microsoft Entra ID',
    desc: 'Deep integration with the MS ecosystem.',
    metric: '38% Adoption',
    category: 'Workforce Identity',
    longDesc: 'Identity fabric tightly integrated with Microsoft 365, endpoint controls, and conditional access.',
    bestFor: 'Organizations centered on Microsoft services and endpoint posture signals.',
    pricingModel: 'Bundled with Microsoft licensing tiers',
    strengths: ['Strong conditional access controls', 'Native Microsoft 365 integration', 'Broad device context'],
    watchouts: ['Cross-cloud identity complexity', 'Conditional access tuning requires discipline'],
    integrationHighlights: ['Conditional Access', 'Privileged Identity Management', 'Identity Protection'],
    icon: Users,
  },
  {
    id: 't3',
    name: 'SailPoint',
    desc: 'Enterprise Identity Governance & Administration.',
    metric: '15% Growth',
    category: 'Identity Governance',
    longDesc: 'Policy-focused governance platform for access reviews, role modeling, and provisioning workflows.',
    bestFor: 'Regulated enterprises with strict certification and SoD controls.',
    pricingModel: 'Enterprise subscription by module',
    strengths: ['Strong governance controls', 'Certification workflows', 'Role mining capabilities'],
    watchouts: ['Long implementation cycles', 'Needs strong data ownership model'],
    integrationHighlights: ['Access certifications', 'Role/entitlement modeling', 'Policy violation reporting'],
    icon: Shield,
  },
  {
    id: 't4',
    name: 'CyberArk',
    desc: 'Gold standard for Privileged Access Management.',
    metric: '99.9% SLA',
    category: 'Privileged Access Management',
    longDesc: 'PAM-first platform for credential vaulting, session isolation, and privileged workflow controls.',
    bestFor: 'High-risk environments requiring strict privileged access controls.',
    pricingModel: 'Seat and capability-based enterprise licensing',
    strengths: ['Mature privileged session controls', 'Credential vaulting', 'Operational resilience'],
    watchouts: ['Operational overhead for policy tuning', 'Integration effort with legacy systems'],
    integrationHighlights: ['Session recording', 'Credential rotation', 'Just-in-time privilege elevation'],
    icon: KeyRound,
  },
];

const trendingTools = [
  {
    id: 'tr1',
    name: 'Teleport',
    desc: 'Identity-native infrastructure access management.',
    metric: '+120% YoY',
    category: 'Infrastructure Access',
    longDesc: 'Certificate-based access broker for SSH, Kubernetes, and databases with strong audit trails.',
    bestFor: 'Platform teams replacing static credentials for infra access.',
    pricingModel: 'Open source + enterprise control plane',
    strengths: ['Short-lived credentials', 'Unified infra access', 'Strong session auditing'],
    watchouts: ['Requires disciplined identity source integration', 'Migration effort from legacy bastions'],
    integrationHighlights: ['Kubernetes access', 'Database access', 'Infrastructure session replay'],
    icon: ShieldCheck,
  },
  {
    id: 'tr2',
    name: 'Clerk',
    desc: 'Developer-first authentication and user management.',
    metric: '+85% DevOps',
    category: 'Developer-Centric Auth',
    longDesc: 'Rapid integration auth platform with prebuilt UI and strong support for modern frontend stacks.',
    bestFor: 'Product teams prioritizing implementation speed and modern UX.',
    pricingModel: 'Free tier + MAU-based pricing',
    strengths: ['Fast implementation', 'Strong DX for frontend teams', 'Modern auth components'],
    watchouts: ['May require custom extensions for complex enterprise policy', 'Vendor dependency for auth UX'],
    integrationHighlights: ['Prebuilt auth flows', 'Multi-session support', 'Webhook/event hooks'],
    icon: Users,
  },
];

const largestThreats = [
  {
    id: 'th-aitm',
    title: 'AiB (Adversary-in-the-Middle) MFA Bypass',
    desc: 'Attackers use reverse proxies to intercept session cookies, bypassing multi-factor authentication entirely.',
    type: 'Session Hijacking',
    trend: '+45%',
    severity: 'critical',
    confidence: 'high',
    responseSla: '4 hours',
    attackPath: 'Phishing link -> reverse proxy login relay -> session token theft -> account takeover.',
    indicators: ['Spike in successful sign-ins from new ASN', 'Session re-use from unusual geo/device'],
    mitigations: ['Phishing-resistant MFA (FIDO2/WebAuthn)', 'Token binding and short session lifetimes'],
  },
  {
    id: 'th-stuffing',
    title: 'Credential Stuffing & Spraying',
    desc: 'Automated injection of breached credentials to take over user accounts at scale.',
    type: 'Auth Abuse',
    trend: '+12%',
    severity: 'high',
    confidence: 'high',
    responseSla: '8 hours',
    attackPath: 'Leaked credential corpus -> distributed bot traffic -> account takeover attempts.',
    indicators: ['Elevated failed login rate', 'High-volume requests from rotating IP pools'],
    mitigations: ['Bot detection and rate limits', 'Passwordless or breached-password checks'],
  },
  {
    id: 'th-oauth-consent',
    title: 'OAuth App Abuse (Consent Phishing)',
    desc: 'Tricking users into granting malicious applications access to their sensitive cloud data.',
    type: 'Social Engineering',
    trend: '+88%',
    severity: 'high',
    confidence: 'medium',
    responseSla: '8 hours',
    attackPath: 'Malicious app registration -> deceptive consent prompt -> token abuse for data access.',
    indicators: ['New app consent spikes', 'Unexpected scopes granted by non-admin users'],
    mitigations: ['Admin-consent workflow', 'Restrict high-risk scopes and app publishers'],
  },
  {
    id: 'th-over-priv',
    title: 'Over-Privileged Cloud Identities',
    desc: 'Cloud IAM roles harboring excessive permissions, providing massive blast radii upon compromise.',
    type: 'Misconfiguration',
    trend: '-5%',
    severity: 'critical',
    confidence: 'medium',
    responseSla: '24 hours',
    attackPath: 'Initial foothold -> role assumption -> privilege escalation -> lateral movement.',
    indicators: ['Dormant roles with admin grants', 'Unusual role-chaining activity'],
    mitigations: ['Least-privilege policy baseline', 'Periodic entitlement reviews and JIT access'],
  },
];

const fallbackNews = [
  {
    id: 'f1',
    title: 'Okta Warns of Recent Credential Stuffing Attacks',
    link: 'https://thehackernews.com/',
    pubDate: '2026-02-20T08:00:00.000Z',
    publishedAtMs: Date.parse('2026-02-20T08:00:00.000Z'),
    source: 'The Hacker News',
    summary: 'Security teams are seeing elevated automated login attempts tied to reused passwords across SaaS tenants.',
    tags: ['Credential Security', 'Bot Defense'],
    riskLevel: 'high',
  },
  {
    id: 'f2',
    title: 'Microsoft Entra ID Introduces New Conditional Access Policies',
    link: 'https://www.microsoft.com/security/business/microsoft-entra',
    pubDate: '2026-02-18T12:30:00.000Z',
    publishedAtMs: Date.parse('2026-02-18T12:30:00.000Z'),
    source: 'Microsoft Security',
    summary: 'New policy templates aim to reduce risky sign-ins by combining device trust, location, and session context.',
    tags: ['Conditional Access', 'Identity Governance'],
    riskLevel: 'medium',
  },
  {
    id: 'f3',
    title: 'Zero Trust Architecture: Why IAM is the Perimeter',
    link: 'https://www.nist.gov/publications/zero-trust-architecture',
    pubDate: '2026-02-12T10:00:00.000Z',
    publishedAtMs: Date.parse('2026-02-12T10:00:00.000Z'),
    source: 'NIST',
    summary: 'Practical guidance on mapping identity controls to zero trust decision points for distributed systems.',
    tags: ['Zero Trust', 'Architecture'],
    riskLevel: 'low',
  },
];

const fallbackVulns = [
  {
    title: 'CVE-2023-XXXX',
    desc: 'Privilege Escalation in Popular IdP',
    severity: 'critical',
    score: '9.8',
    type: 'Authentication Bypass',
  },
  {
    title: 'CVE-2024-YYYY',
    desc: 'OAuth Token Leakage',
    severity: 'high',
    score: '7.5',
    type: 'Information Disclosure',
  },
  {
    title: 'CVE-2023-ZZZZ',
    desc: 'Directory Traversal in IAM Portal',
    severity: 'high',
    score: '8.1',
    type: 'Path Traversal',
  },
];

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8081/api/v1').replace(/\/$/, '');
const BRIEFING_URL = `${API_BASE_URL}/intelligence/briefing`;

function formatDate(pubDate) {
  if (!pubDate) return 'Recent';
  const parsed = new Date(pubDate);
  if (Number.isNaN(parsed.getTime())) return 'Recent';
  return parsed.toLocaleDateString();
}

function formatRelativeAge(publishedAtMs, nowMs) {
  if (!publishedAtMs || Number.isNaN(publishedAtMs)) {
    return 'Time unknown';
  }

  if (!nowMs || Number.isNaN(nowMs)) {
    return 'Recent';
  }

  const diffMs = nowMs - publishedAtMs;
  if (diffMs < 0) {
    return 'Just now';
  }

  const hourMs = 60 * 60 * 1000;
  const dayMs = 24 * hourMs;

  if (diffMs < hourMs) {
    const minutes = Math.max(1, Math.round(diffMs / (60 * 1000)));
    return `${minutes}m ago`;
  }

  if (diffMs < dayMs) {
    const hours = Math.round(diffMs / hourMs);
    return `${hours}h ago`;
  }

  const days = Math.round(diffMs / dayMs);
  return `${days}d ago`;
}

function normalizeSeverity(value) {
  const severity = String(value || 'unknown').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(severity)) {
    return severity;
  }
  return 'medium';
}

function normalizeRisk(value) {
  const risk = String(value || 'low').toLowerCase();
  if (['high', 'medium', 'low'].includes(risk)) {
    return risk;
  }
  return 'low';
}

function normalizeBriefingNews(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  return items
    .map((item, index) => {
      const publishedAtMs = typeof item?.publishedAtMs === 'number' ? item.publishedAtMs : null;
      return {
        id: item?.id || `briefing-news-${index}`,
        title: item?.title || 'Untitled article',
        link: item?.link || '#',
        pubDate: item?.publishedAt || null,
        publishedAtMs,
        source: item?.source || 'Unknown source',
        summary: item?.summary || 'No summary available.',
        tags: Array.isArray(item?.tags) ? item.tags.slice(0, 3) : ['IAM', 'Security'],
        riskLevel: normalizeRisk(item?.risk),
      };
    })
    .filter((item) => typeof item.link === 'string' && item.link.startsWith('http'));
}

function normalizeBriefingThreats(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  return items.map((item, index) => ({
    id: item?.id || `threat-${index}`,
    title: item?.title || 'Unknown threat',
    desc: item?.attackPath || item?.title || 'No detail available',
    type: item?.classification || 'Threat',
    trend: item?.trend || 'N/A',
    severity: normalizeSeverity(item?.severity),
    confidence: item?.confidence || 'medium',
    responseSla: item?.responseSla || '72 hours',
    attackPath: item?.attackPath || 'No attack path provided.',
    indicators: Array.isArray(item?.indicators) ? item.indicators : ['No indicators provided.'],
    mitigations: Array.isArray(item?.mitigations) ? item.mitigations : ['No mitigations provided.'],
  }));
}

function normalizeBriefingVulnerabilities(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  return items.map((item) => ({
    title: item?.cveId || 'Unknown CVE',
    desc: item?.summary || 'No English description available.',
    severity: normalizeSeverity(item?.severity),
    score: typeof item?.cvssScore === 'number' ? item.cvssScore.toFixed(1) : 'N/A',
    type: 'CVE Record',
    referenceUrl: typeof item?.reference === 'string' ? item.reference : null,
  }));
}

function downloadCsv(filename, rows) {
  const csvText = toCsv(rows);
  const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8' });
  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(blobUrl);
}

function Skeleton({ count = 3, type = "row" }) {
  return (
    <div className="skeleton-wrapper" aria-hidden="true">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className={`skeleton-box skeleton-${type}`} />
      ))}
    </div>
  );
}

function App() {
  const [news, setNews] = useState(fallbackNews);
  const [threats, setThreats] = useState(largestThreats);
  const [vulns, setVulns] = useState(fallbackVulns);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [nowTs, setNowTs] = useState(() => Date.now());
  const [newsWindow, setNewsWindow] = useState('24h');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [selectedToolId, setSelectedToolId] = useState(topTools[0].id);
  const [selectedMatrixId, setSelectedMatrixId] = useState(largestThreats[0].id);
  const activeRequestRef = useRef(null);

  const fetchData = useCallback(async ({ initialLoad = false, window = newsWindow } = {}) => {
    const controller = new AbortController();
    if (activeRequestRef.current) {
      activeRequestRef.current.abort();
    }
    activeRequestRef.current = controller;

    if (!initialLoad) {
      setLoading(true);
      setRefreshing(true);
      setLoadError(null);
    }

    let nextNews = fallbackNews;
    let nextThreats = largestThreats;
    let nextVulns = fallbackVulns;
    let apiFailed = false;

    try {
      const briefingData = await fetchJson(`${BRIEFING_URL}?window=${window}`, {
        timeoutMs: 6500,
        retries: 1,
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });

      const parsedNews = normalizeBriefingNews(briefingData.news);
      const parsedThreats = normalizeBriefingThreats(briefingData.threats);
      const parsedVulns = normalizeBriefingVulnerabilities(briefingData.vulnerabilities);

      if (parsedNews.length > 0) {
        nextNews = parsedNews;
      }
      if (parsedThreats.length > 0) {
        nextThreats = parsedThreats;
      }
      if (parsedVulns.length > 0) {
        nextVulns = parsedVulns;
      }

      if (briefingData.stale) {
        setLoadError('Live feeds are degraded. Showing cached intelligence from the backend.');
      } else {
        setLoadError(null);
      }
    } catch {
      apiFailed = true;
    }

    if (!controller.signal.aborted) {
      setNews(nextNews);
      setThreats(nextThreats);
      setVulns(nextVulns);
      if (apiFailed) {
        setLoadError('Intelligence API unavailable. Displaying local fallback intelligence.');
      }
      setLoading(false);
      setRefreshing(false);
    }

    if (activeRequestRef.current === controller) {
      activeRequestRef.current = null;
    }
  }, [newsWindow]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      setNowTs(Date.now());
    }, 60 * 1000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    const timerId = window.setTimeout(() => {
      void fetchData({ initialLoad: true, window: newsWindow });
    }, 0);
    return () => {
      window.clearTimeout(timerId);
      if (activeRequestRef.current) {
        activeRequestRef.current.abort();
      }
    };
  }, [fetchData, newsWindow]);

  const marketSolutions = useMemo(() => [...topTools, ...trendingTools], []);

  const selectedTool = useMemo(
    () => marketSolutions.find((tool) => tool.id === selectedToolId) || marketSolutions[0],
    [marketSolutions, selectedToolId],
  );

  const filteredNews = useMemo(() => {
    const now = nowTs;
    const rangeMs = newsWindow === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
    const maxItems = newsWindow === '24h' ? 4 : 8;

    const inWindow = news
      .filter((item) => {
        if (!item.publishedAtMs || Number.isNaN(item.publishedAtMs)) {
          return newsWindow === '7d';
        }
        const age = now - item.publishedAtMs;
        return age >= 0 && age <= rangeMs;
      })
      .sort((a, b) => (b.publishedAtMs || 0) - (a.publishedAtMs || 0));

    if (inWindow.length > 0) {
      return inWindow.slice(0, maxItems);
    }

    return [...news]
      .sort((a, b) => (b.publishedAtMs || 0) - (a.publishedAtMs || 0))
      .slice(0, maxItems);
  }, [news, newsWindow, nowTs]);

  const newsCoverageLabel = useMemo(() => {
    const label = newsWindow === '24h' ? 'last 24 hours' : 'last 7 days';
    return `Showing ${filteredNews.length} items from the ${label}.`;
  }, [filteredNews.length, newsWindow]);

  const combinedRows = useMemo(
    () => [
      ...threats.map((threat) => ({
        id: threat.id,
        title: threat.title,
        classification: threat.type,
        severity: threat.severity,
        metric: threat.trend,
        description: threat.desc,
        confidence: threat.confidence,
        responseSla: threat.responseSla,
        attackPath: threat.attackPath,
        indicators: threat.indicators,
        mitigations: threat.mitigations,
        referenceUrl: null,
      })),
      ...vulns.map((vuln) => ({
        id: `cve-${vuln.title}`,
        title: vuln.title,
        classification: vuln.type,
        severity: vuln.severity,
        metric: `CVSS ${vuln.score}`,
        description: vuln.desc,
        confidence: Number(vuln.score) >= 9 ? 'high' : 'medium',
        responseSla: Number(vuln.score) >= 9 ? '24 hours' : '72 hours',
        attackPath: 'Exploitability depends on affected product version and deployment exposure.',
        indicators: ['New exploit PoC publication', 'Unexpected crash/authentication failures tied to vulnerable component'],
        mitigations: ['Patch affected systems based on vendor advisory', 'Add temporary compensating controls at edge/WAF'],
        referenceUrl: vuln.referenceUrl || (
          /^CVE-\d{4}-\d+$/i.test(vuln.title)
            ? `https://nvd.nist.gov/vuln/detail/${vuln.title.toUpperCase()}`
            : null
        ),
      })),
    ],
    [threats, vulns],
  );

  const filteredRows = useMemo(
    () =>
      combinedRows.filter((row) => {
        const matchesSeverity = severityFilter === 'all' || row.severity.toLowerCase() === severityFilter;
        const matchesType =
          typeFilter === 'all' ||
          (typeFilter === 'cve' ? row.classification === 'CVE Record' : row.classification !== 'CVE Record');
        return matchesSeverity && matchesType;
      }),
    [combinedRows, severityFilter, typeFilter],
  );

  const selectedMatrixItem = useMemo(
    () => filteredRows.find((row) => row.id === selectedMatrixId) || filteredRows[0] || null,
    [filteredRows, selectedMatrixId],
  );

  const handleExportCsv = useCallback(() => {
    const filename = `iam-news-${new Date().toISOString().slice(0, 10)}.csv`;
    downloadCsv(filename, filteredRows);
  }, [filteredRows]);

  return (
    <div className="dashboard-container page-animate">

      {/* Hero Header Region */}
      <header className="hero-section">
        <div className="hero-content">
          <div className="gradient-icon-bg">
            <ShieldBan size={30} color="var(--accent-primary)" aria-hidden="true" />
          </div>
          <div className="hero-text">
            <h1 className="gradient-text">Identity Intelligence</h1>
            <p className="hero-subtitle">Executive summary of IAM threats, tool landscapes, and market movement.</p>
          </div>
        </div>

        {/* Key Actions */}
        <div className="hero-actions">
          <button className="btn-secondary" onClick={handleExportCsv}>
            <Download size={16} /> Export CSV
          </button>
          <button
            className="btn-primary"
            onClick={() => {
              void fetchData();
            }}
            disabled={refreshing}
            aria-label="Refresh dashboard data"
          >
            <RefreshCw size={16} className={refreshing ? 'spinning' : ''} aria-hidden="true" />
            {refreshing ? 'Syncing...' : 'Live Refresh'}
          </button>
        </div>
      </header>

      {loadError ? (
        <div className="status-banner" role="status" aria-live="polite">
          {loadError}
        </div>
      ) : null}

      <main className="bento-grid">

        {/* News Section */}
        <section className="card news-section" aria-labelledby="news-heading">
          <header className="card-header">
            <h2 id="news-heading" className="card-title">
              <Newspaper size={18} color="var(--accent-primary)" aria-hidden="true" />
              Intelligence Briefing
            </h2>
            <select
              className="select-sm"
              aria-label="Filter news"
              value={newsWindow}
              onChange={(event) => {
                setNewsWindow(event.target.value);
              }}
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
            </select>
          </header>

          <div className="card-content">
            {!loading ? <p className="news-coverage">{newsCoverageLabel}</p> : null}
            {loading ? (
              <Skeleton count={2} type="card" />
            ) : (
              filteredNews.length === 0 ? (
                <div className="empty-state">
                  <ShieldAlert size={32} color="var(--text-tertiary)" aria-hidden="true" />
                  <p>No intelligence items available for the selected time range.</p>
                </div>
              ) : (
                <div className="news-grid">
                  {filteredNews.map((item) => (
                    <a href={item.link} target="_blank" rel="noopener noreferrer" className="news-card" key={item.id}>
                      <div className="news-source">
                        <ExternalLink size={12} /> {(item.source && typeof item.source === 'string') ? item.source : 'The Hacker News'}
                      </div>
                      <h3>{item.title}</h3>
                      <p className="news-summary">{item.summary}</p>
                      <div className="news-tags">
                        {item.tags?.map((tag) => (
                          <span key={`${item.id}-${tag}`} className="news-tag">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <div className="news-footer">
                        <span>{formatDate(item.pubDate)} • {formatRelativeAge(item.publishedAtMs, nowTs)}</span>
                        <span className={`badge-subtle risk-badge risk-${item.riskLevel || 'low'}`}>
                          {String(item.riskLevel || 'low').toUpperCase()} risk
                        </span>
                      </div>
                    </a>
                  ))}
                </div>
              )
            )}
          </div>
        </section>

        {/* Tools Section */}
        <section className="card tools-section" aria-labelledby="tools-heading">
          <header className="card-header">
            <h2 id="tools-heading" className="card-title">
              <Wrench size={18} color="var(--accent-cyan)" aria-hidden="true" />
              Market Solutions
            </h2>
            <span className="section-hint">Select a solution for deeper context</span>
          </header>

          <div className="card-content">
            <div className="tool-list">
              {topTools.map((t) => {
                const Icon = t.icon;
                return (
                  <button
                    type="button"
                    className={`tool-item tool-item-button ${selectedTool.id === t.id ? 'is-selected' : ''}`}
                    key={t.id}
                    onClick={() => {
                      setSelectedToolId(t.id);
                    }}
                    aria-pressed={selectedTool.id === t.id}
                  >
                    <div className="tool-icon"><Icon size={16} /></div>
                    <div className="tool-info">
                      <div className="tool-name-row">
                        <span className="tool-name">{t.name}</span>
                        <span className="tool-metric">{t.metric}</span>
                      </div>
                      <span className="tool-desc">{t.desc}</span>
                    </div>
                  </button>
                );
              })}

              <div role="separator" style={{ height: '1px', background: 'var(--border-color)', margin: 'var(--space-2) 0' }}></div>

              {trendingTools.map((t) => {
                const Icon = t.icon;
                return (
                  <button
                    type="button"
                    className={`tool-item tool-item-button ${selectedTool.id === t.id ? 'is-selected' : ''}`}
                    key={t.id}
                    onClick={() => {
                      setSelectedToolId(t.id);
                    }}
                    aria-pressed={selectedTool.id === t.id}
                  >
                    <div className="tool-icon"><Icon size={16} /></div>
                    <div className="tool-info">
                      <div className="tool-name-row">
                        <span className="tool-name">{t.name}</span>
                        <span className="tool-metric" style={{ color: 'var(--accent-success)' }}>{t.metric}</span>
                      </div>
                      <span className="tool-desc">{t.desc}</span>
                    </div>
                  </button>
                );
              })}
            </div>

            <aside className="detail-panel" aria-live="polite">
              <div className="detail-header">
                <h3>{selectedTool.name}</h3>
                <span className="badge-subtle">{selectedTool.category}</span>
              </div>
              <p className="detail-copy">{selectedTool.longDesc}</p>
              <div className="detail-meta-grid">
                <div>
                  <span className="detail-label">Best fit</span>
                  <p>{selectedTool.bestFor}</p>
                </div>
                <div>
                  <span className="detail-label">Pricing</span>
                  <p>{selectedTool.pricingModel}</p>
                </div>
              </div>
              <div className="detail-columns">
                <div>
                  <h4>Strengths</h4>
                  <ul>
                    {selectedTool.strengths.map((strength) => (
                      <li key={strength}>{strength}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4>Watchouts</h4>
                  <ul>
                    {selectedTool.watchouts.map((watchout) => (
                      <li key={watchout}>{watchout}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div>
                <span className="detail-label">Integration highlights</span>
                <p className="detail-inline-list">{selectedTool.integrationHighlights.join(' • ')}</p>
              </div>
            </aside>
          </div>
        </section>

        {/* Dense Data: Threats & Vulns */}
        <section className="card threats-section" aria-labelledby="data-heading">
          <header className="card-header">
            <h2 id="data-heading" className="card-title">
              <Activity size={18} color="var(--accent-purple)" aria-hidden="true" />
              Active Threat Matrix
            </h2>
            <div style={{ display: 'flex', gap: '8px' }}>
              <span className="section-hint">Select a row for mitigation guidance</span>
              <select
                className="select-sm"
                aria-label="Severity filter"
                value={severityFilter}
                onChange={(event) => {
                  setSeverityFilter(event.target.value);
                }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                className="select-sm"
                aria-label="Type filter"
                value={typeFilter}
                onChange={(event) => {
                  setTypeFilter(event.target.value);
                }}
              >
                <option value="all">Vulnerabilities & Tactics</option>
                <option value="cve">CVEs Only</option>
                <option value="threat">Threat Tactics Only</option>
              </select>
            </div>
          </header>

          <div className="card-content" style={{ paddingTop: 0 }}>
            {loading ? (
              <Skeleton count={4} type="row" />
            ) : (
              <div className="data-table-wrapper">
                {filteredRows.length === 0 ? (
                  <div className="empty-state">
                    <ShieldAlert size={32} color="var(--text-tertiary)" aria-hidden="true" />
                    <p>No active threats match the current filters.</p>
                  </div>
                ) : (
                  <table className="data-table" aria-label="Threats and Vulnerabilities Matrix">
                    <thead>
                      <tr>
                        <th>Identifier / Title</th>
                        <th>Classification</th>
                        <th>Severity</th>
                        <th>Metric / Trend</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredRows.map((row) => (
                        <tr
                          key={row.id}
                          className={`matrix-row ${selectedMatrixItem?.id === row.id ? 'is-selected' : ''}`}
                          tabIndex={0}
                          onClick={() => {
                            setSelectedMatrixId(row.id);
                          }}
                          onKeyDown={(event) => {
                            if (event.key === 'Enter' || event.key === ' ') {
                              event.preventDefault();
                              setSelectedMatrixId(row.id);
                            }
                          }}
                        >
                          <td>
                            <div className="table-title" style={{ fontFamily: row.id.startsWith('cve-') ? 'monospace' : 'inherit' }}>
                              {row.title}
                            </div>
                            <div className="table-desc">{row.description}</div>
                          </td>
                          <td><span className="badge-subtle">{row.classification}</span></td>
                          <td>
                            <span className={`severity-indicator severity-${normalizeSeverity(row.severity)}`}>
                              <span className="severity-dot" aria-hidden="true"></span>
                              {row.severity}
                            </span>
                          </td>
                          <td style={{ fontFamily: row.metric.startsWith('CVSS') ? 'monospace' : 'inherit' }}>
                            {row.metric}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {selectedMatrixItem ? (
              <aside className="detail-panel" aria-live="polite">
                <div className="detail-header">
                  <h3>{selectedMatrixItem.title}</h3>
                  <span className={`severity-indicator severity-${normalizeSeverity(selectedMatrixItem.severity)}`}>
                    <span className="severity-dot" aria-hidden="true"></span>
                    {selectedMatrixItem.severity}
                  </span>
                </div>
                <p className="detail-copy">{selectedMatrixItem.description}</p>
                <div className="detail-meta-grid">
                  <div>
                    <span className="detail-label">Classification</span>
                    <p>{selectedMatrixItem.classification}</p>
                  </div>
                  <div>
                    <span className="detail-label">Priority SLA</span>
                    <p>{selectedMatrixItem.responseSla}</p>
                  </div>
                  <div>
                    <span className="detail-label">Signal confidence</span>
                    <p>{selectedMatrixItem.confidence}</p>
                  </div>
                </div>
                <div>
                  <span className="detail-label">Likely attack path</span>
                  <p>{selectedMatrixItem.attackPath}</p>
                </div>
                <div className="detail-columns">
                  <div>
                    <h4>Detection indicators</h4>
                    <ul>
                      {selectedMatrixItem.indicators.map((indicator) => (
                        <li key={indicator}>{indicator}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4>Recommended mitigations</h4>
                    <ul>
                      {selectedMatrixItem.mitigations.map((mitigation) => (
                        <li key={mitigation}>{mitigation}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                {selectedMatrixItem.referenceUrl ? (
                  <p>
                    <a href={selectedMatrixItem.referenceUrl} target="_blank" rel="noopener noreferrer" className="detail-link">
                      Open primary reference
                    </a>
                  </p>
                ) : null}
              </aside>
            ) : null}
          </div>
        </section>

      </main>

    </div>
  );
}

export default App;
