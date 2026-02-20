const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

export function safeExternalUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) {
    return null;
  }

  try {
    const parsed = new URL(rawUrl);
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}
