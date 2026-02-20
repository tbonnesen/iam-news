# Minimal E2E Strategy

Use Playwright in CI against a production build preview:

1. Start app with `npm run build && npm run preview -- --host 0.0.0.0 --port 4173`.
2. Verify landing page renders the hero title and threat table.
3. Trigger `Live Refresh` and assert loading state transition.
4. Validate `Export CSV` downloads a file with header row.
5. Confirm external article links open in a new tab with `rel="noopener noreferrer"`.

This repository currently implements unit/integration tests only; add Playwright when browser CI is enabled.
