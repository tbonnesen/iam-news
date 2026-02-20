export type NewsRisk = 'low' | 'medium' | 'high';

export type NewsItem = {
  id: string;
  title: string;
  summary: string;
  link: string;
  source: string;
  publishedAt: string | null;
  publishedAtMs: number | null;
  tags: string[];
  risk: NewsRisk;
};

export type ThreatItem = {
  id: string;
  title: string;
  classification: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  trend: string;
  confidence: 'low' | 'medium' | 'high';
  responseSla: string;
  attackPath: string;
  indicators: string[];
  mitigations: string[];
};

export type VulnerabilityItem = {
  cveId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number | null;
  summary: string;
  reference: string;
};

export type BriefingWindow = '24h' | '7d';

export type IntelligenceBriefing = {
  generatedAt: string;
  window: BriefingWindow;
  stale: boolean;
  news: NewsItem[];
  threats: ThreatItem[];
  vulnerabilities: VulnerabilityItem[];
};

export type AuthContext = {
  sub: string;
  roles: string[];
};
