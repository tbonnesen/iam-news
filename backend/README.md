# IAM News API (Backend)

Security-hardened Fastify BFF for external intelligence feeds.

## Run

```bash
cp .env.example .env
npm ci
npm run dev
```

## Endpoints
- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/intelligence/briefing?window=24h|7d&limit=1..20`
- `POST /api/v1/intelligence/admin/refresh` (requires Bearer token with `admin` role + `Idempotency-Key` header)

## Security defaults
- Strict CORS allowlist
- Helmet headers + CSP
- Global rate limiting
- JWT auth for admin operations
- URL vetting for refreshed links (HTTPS + vetted host allowlist + private-network blocking)
- Structured logs with secret redaction
- Timeout/retry policy for upstream APIs
