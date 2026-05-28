# Cyber-Guardian Production Runbook

This file lists the minimum production setup for Cyber-Guardian.

## Required Vercel Environment Variables

Set these in Vercel Project Settings -> Environment Variables:

```text
ANTHROPIC_API_KEY=...
ANTHROPIC_MODEL=claude-sonnet-4-6
ANTHROPIC_MAX_TOKENS=1500
ANTHROPIC_TIMEOUT_MS=25000

SUPABASE_URL=...
SUPABASE_SERVICE_KEY=...

ALLOWED_ORIGINS=https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app
CG_ADMIN_BYPASS_SECRET=generate-a-long-random-secret

SCAN_USAGE_MODE=strict
SCAN_MAX_REQUESTS_PER_MINUTE=5
SCAN_MAX_REQUESTS_PER_HOUR=20
SCAN_MAX_FREE_SCANS_PER_MONTH=7
SCAN_MAX_API_CALLS_PER_DAY=5000
SCAN_MAX_INPUT_SIZE_CHARS=50000
SCAN_MIN_INPUT_SIZE_CHARS=5
SCAN_CACHE_TTL_SECONDS=3600
```

Use `SCAN_USAGE_MODE=strict` in production after the Supabase SQL migration has been run.
Use `SCAN_USAGE_MODE=fallback` only during setup or local development.

## Developer Bypass

`CG_ADMIN_BYPASS_SECRET` lets the site owner run unlimited scans without changing
the public 7-scan monthly limit for normal visitors. Keep it private.

After setting it in Vercel and redeploying, enable it in your own browser console:

```js
localStorage.setItem('cg-admin-secret', 'PASTE_THE_SECRET_HERE')
```

To disable it in that browser:

```js
localStorage.removeItem('cg-admin-secret')
```

For GitHub Actions or the automatic scanner, add the same value as a secret named
`CG_ADMIN_BYPASS_SECRET`. Bypassed scans still write safe metadata to `site_scans`,
so the dashboard continues updating normally.

## Editing Public Text

Open `/content-admin.html`, paste the same `CG_ADMIN_BYPASS_SECRET`, choose the
area, language, and text key, then save the replacement text. Saved values are
stored in Supabase `site_content_overrides`.

Public visitors can read those text overrides through `/api/content`, but only
requests with the admin secret can write changes.

## Supabase Migration

Run this SQL once in Supabase SQL Editor:

```text
supabase/migrations/001_scan_usage_limits.sql
supabase/migrations/002_site_content_overrides.sql
```

This creates:

- `public.cg_scan_usage_windows`
- `public.cg_consume_scan_usage(...)`
- `public.site_content_overrides`

The API calls this RPC before calling Anthropic. If the request exceeds minute, hour,
day, or monthly quota, the request stops before any model cost is incurred.

## Limit Guidance

The global daily cap is a cost safety breaker. It is not a business plan.

Recommended launch defaults:

- `SCAN_MAX_REQUESTS_PER_MINUTE=5`
- `SCAN_MAX_REQUESTS_PER_HOUR=20`
- `SCAN_MAX_FREE_SCANS_PER_MONTH=7`
- `SCAN_MAX_API_CALLS_PER_DAY=1000-5000`

Choose the daily cap from budget:

```text
daily_cap = daily_budget_usd / average_scan_cost_usd
```

Start low, monitor, then increase.

## Production Checks Before Launch

- Confirm `ALLOWED_ORIGINS` has no `*`.
- Confirm `SCAN_USAGE_MODE=strict`.
- Confirm Supabase RPC works before public launch.
- Confirm Vercel logs do not print user code, emails, API keys, or Supabase errors to users.
- Confirm the scanner does not execute submitted code.
- Confirm privacy/terms say whether user-submitted code may be sent to a third-party AI provider.

## Current Known Limits

- Free quota is currently IP-based, not account-based.
- Enterprise/private scanning should add accounts, API keys, and org-level quotas.
- The AI verdict should be supported by deterministic rules for stronger auditability.
