# IAM News Dashboard

Production-minded frontend dashboard for IAM market intelligence and vulnerability awareness. The app currently renders a React single-page UI and fetches public intelligence feeds.

## Project context (assumed)
- What we are building: A read-only IAM threat and market intelligence dashboard for security leaders.
- Users and scale: 100-5,000 users, bursty reads, p95 render under 2.5s, p95 data refresh under 5s.
- Platform: Web frontend (React + Vite).
- Deployment target: Containerized static site on NGINX behind a cloud load balancer/CDN.
- Data sensitivity: Internal-use operational intelligence; no direct PII storage today.
- Compliance requirements: None mandated yet; SOC2-style controls recommended.
- Team constraints: JavaScript/React stack, fast iteration, low operational overhead.
- Non-goals: No user-generated content, no direct write APIs, no in-browser secret handling.
- External integrations: NVD API and RSS2JSON feed adapter.

## Architecture overview

```text
[Browser]
  | HTTPS
  v
[React SPA]
  | fetch (public feeds)
  +--> [RSS2JSON -> The Hacker News feed]
  +--> [NVD CVE API]

Trust boundary #1: Internet client -> app host
Trust boundary #2: Browser -> third-party APIs
```

Current state is client-heavy; next production step is a backend-for-frontend (BFF) proxy to centralize validation, caching, rate limiting, and telemetry.

## Security posture in this repo
- Safe external links: News URLs are protocol-allowlisted (`http`/`https`) before rendering.
- Resilient network client: timeouts + bounded retry/backoff for external calls.
- Safer defaults: fallback datasets when external sources fail.
- Security headers at runtime: `nginx.conf` adds CSP, frame protections, referrer policy, and MIME-sniff prevention.
- No secrets in code: `.env.example` only; no credentials committed.

## Threat model summary
- Assets: integrity of rendered intelligence, app availability, build pipeline integrity.
- Entry points: external feed payloads, browser runtime, CI dependency supply chain.
- Primary attacker goals:
  - Inject malicious links or payloads through upstream feeds.
  - Degrade availability via slow or failing dependencies.
  - Introduce vulnerable dependencies in CI.
- Relevant OWASP categories: A03 Injection, A05 Security Misconfiguration, A06 Vulnerable Components, A08 Software/Data Integrity Failures.

## Local development

### Prerequisites
- Node.js 22+
- npm 10+

### Setup
```bash
npm ci
npm run dev
```

### Quality checks
```bash
npm run lint
npm run test
npm run build
npm run check
```

## Test strategy
- Unit tests: `tests/unit` for deterministic helpers (URL sanitization).
- Integration tests: `tests/integration` for parser and network utility behavior.
- Minimal E2E strategy: documented in `tests/e2e/README.md` for future Playwright automation.

## Pre-commit hook
```bash
git config core.hooksPath .githooks
```

Hook runs:
- `npm run lint`
- `npm run test`

## Containerized run

### Build and run with Docker Compose
```bash
docker compose up --build
```

App is served at `http://localhost:8080`.

## CI/CD template
GitHub Actions workflow in `.github/workflows/ci.yml` includes:
- Lint, tests, build
- `npm audit` dependency scan
- Dependency review action on pull requests
- CodeQL static analysis
- CycloneDX SBOM artifact generation

## Operational runbook

### Health checks
- Build health: `npm run build`
- Static runtime check: load `/` and verify title + threat matrix render.

### Incident response
1. If feeds fail, UI falls back to static datasets and shows a warning banner.
2. Validate upstream APIs from ops environment.
3. If failure persists, keep fallback mode and open an incident ticket.
4. If compromised feed content is suspected, block source domain at edge and rotate to trusted mirror.

### Deployment controls
- Enforce HTTPS and HSTS at load balancer/CDN layer.
- Keep immutable build artifacts and deploy by digest/tag.
- Roll back by reverting to previous known-good image.

## Recommended next hardening step
Move external feed access from browser to a backend proxy module with request validation, allowlisting, caching, rate limits, and audit telemetry.
