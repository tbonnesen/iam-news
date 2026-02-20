import { isIP } from 'node:net';

type VetFailureReason =
  | 'empty-url'
  | 'invalid-url'
  | 'unsupported-protocol'
  | 'credentials-not-allowed'
  | 'private-network-target'
  | 'unvetted-host';

export type VettedUrlResult =
  | { ok: true; url: string; hostname: string }
  | { ok: false; reason: VetFailureReason };

function isPrivateIpv4(host: string): boolean {
  const parts = host.split('.').map((part) => Number(part));
  if (
    parts.length !== 4 ||
    parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)
  ) {
    return false;
  }

  const a = parts[0] ?? -1;
  const b = parts[1] ?? -1;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isPrivateIpv6(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === '::1' || normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd');
}

function isPrivateOrLocalHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();

  if (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.internal')
  ) {
    return true;
  }

  const ipVersion = isIP(normalized);
  if (ipVersion === 4) {
    return isPrivateIpv4(normalized);
  }
  if (ipVersion === 6) {
    return isPrivateIpv6(normalized);
  }

  return false;
}

function hostMatchesPattern(hostname: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return hostname === base || hostname.endsWith(`.${base}`);
  }
  return hostname === pattern;
}

function isVettedHost(hostname: string, vettedHosts: string[]): boolean {
  const normalizedHost = hostname.toLowerCase();
  return vettedHosts.some((pattern) => hostMatchesPattern(normalizedHost, pattern.toLowerCase()));
}

export function vetExternalUrl(raw: string | undefined, vettedHosts: string[]): VettedUrlResult {
  if (!raw || raw.trim().length === 0) {
    return { ok: false, reason: 'empty-url' };
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid-url' };
  }

  if (parsed.protocol !== 'https:') {
    return { ok: false, reason: 'unsupported-protocol' };
  }

  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'credentials-not-allowed' };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (isPrivateOrLocalHost(hostname)) {
    return { ok: false, reason: 'private-network-target' };
  }

  if (!isVettedHost(hostname, vettedHosts)) {
    return { ok: false, reason: 'unvetted-host' };
  }

  return {
    ok: true,
    url: parsed.toString(),
    hostname
  };
}
