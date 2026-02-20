# IAM News Platform

IAM threat and market-intelligence platform with a React frontend and a security-hardened backend-for-frontend (BFF) API.

## What this repo contains
- Frontend: `React + Vite` dashboard (`/src`)
- Backend: `TypeScript + Fastify` API (`/backend`)
- CI/CD security controls (`/.github/workflows/ci.yml`)
- Containerized local runtime (`Dockerfile`, `backend/Dockerfile`, `docker-compose.yml`)

## Architecture overview

```text
[User Browser]
  | HTTPS
  v
[Web SPA (Vite/React)]
  | /api/v1/intelligence/*
  v
[Fastify BFF API]
  |-- zod validation
  |-- rate limiting
  |-- CORS + helmet
  |-- JWT auth for admin routes
  |-- structured logging + request IDs
  |
  +--> [RSS2JSON / news feed]
  +--> [NVD API]

Trust boundary A: Internet -> Web/API
Trust boundary B: API -> 3rd-party upstream feeds
```

## Security summary
- Input validation: Zod request schemas for query/body.
- Output safety: only `http`/`https` links accepted from upstream content.
- Abuse controls: global rate limit and bounded query limits.
- AuthZ: admin refresh endpoint requires JWT with `admin` role.
- Idempotency: admin refresh requires `Idempotency-Key` and deduplicates repeated requests.
- Upstream resilience: timeout + retry + stale-cache fallback.
- URL safety gate: backend only emits links that pass vetted host allowlist + HTTPS + private-network checks.
- Secrets: environment-driven config (`backend/.env.example`), no secrets in code.
- Supply chain: lockfiles + CI dependency audit + dependency review + SBOM + CodeQL.

## Threat model (high-level)
Assets:
- Intelligence feed integrity
- API availability
- Audit logs and admin actions

Entry points:
- `/api/v1/intelligence/briefing`
- `/api/v1/intelligence/admin/refresh`
- Upstream feed payloads
- CI dependency graph

Primary attacker goals:
- Inject malicious feed links/content
- Trigger API exhaustion
- Abuse admin refresh operation

## Local development

### Prerequisites
- Node.js 22+
- npm 10+

### Frontend
```bash
npm ci
npm run dev
```

### Backend
```bash
cd backend
cp .env.example .env
npm ci
npm run dev
```

### Full quality gate
```bash
npm run check
npm --prefix backend run check
```

### Optional unified check
```bash
npm run check:all
```

## Docker
```bash
docker compose up --build
```
- Web: `http://localhost:8080`
- API: `http://localhost:8081`

## API quick reference
- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/intelligence/briefing?window=24h|7d&limit=1..20`
- `POST /api/v1/intelligence/admin/refresh`
  - Requires `Authorization: Bearer <jwt-with-admin-role>`
  - Requires `Idempotency-Key` header

## Operational runbook

### Health checks
- API liveness/readiness: `/health/live` and `/health/ready`
- UI check: dashboard loads and Intelligence Briefing shows data for selected window.

### Incident handling
1. If upstream APIs fail, API serves stale cached data where available.
2. Check API logs by request ID and upstream error rates.
3. If cache stale and upstream outage persists, notify stakeholders and keep read-only mode.
4. Re-run admin refresh after upstream recovery.

### Security operations
- Rotate `JWT_HS256_SECRET` periodically (or migrate to asymmetric keys + JWKS).
- Restrict `CORS_ORIGINS` to production domains.
- Review admin refresh audit logs for unusual activity.
