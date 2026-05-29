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
SITE_URL=https://cyberguardianscan.com

STRIPE_SECRET_KEY=sk_live_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_TEAM=price_...
STRIPE_PRICE_BUSINESS=price_...

RESEND_API_KEY=re_...
SUBSCRIBE_NOTIFY_TO=sales@cyberguardianscan.com
CONTACT_SALES_TO=sales@cyberguardianscan.com
CONTACT_SUPPORT_TO=support@cyberguardianscan.com
EMAIL_FROM=Cyber-Guardian <notifications@cyberguardianscan.com>

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

## Payments

Create three recurring monthly prices in Stripe and copy their price IDs into:

- `STRIPE_PRICE_PRO`
- `STRIPE_PRICE_TEAM`
- `STRIPE_PRICE_BUSINESS`

The pricing buttons call `/api/create-checkout-session`, which creates a Stripe
Checkout subscription session on the server and redirects the visitor to Stripe.
Keep `STRIPE_SECRET_KEY` server-side only in Vercel environment variables.

## Email Lead Notifications

The threat-alert signup form posts to `/api/subscribe`. Each valid email is saved
to Supabase `email_subscribers` and, when `RESEND_API_KEY` is configured, a lead
notification is sent to `SUBSCRIBE_NOTIFY_TO` (default:
`sales@cyberguardianscan.com`).

Resend requires an API key and a verified sending domain before production email
delivery. Keep `RESEND_API_KEY` server-side only in Vercel environment variables.

## Contact Form

The contact buttons link to `/contact.html` instead of `mailto:` links, so visitors
stay inside the site instead of opening Outlook/Microsoft Mail. The form posts to
`/api/contact`, saves messages in Supabase `contact_messages`, and sends email
notifications through Resend.

Sales and enterprise requests go to `CONTACT_SALES_TO`; support and security
requests go to `CONTACT_SUPPORT_TO`.

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

## Automatic Scanner Scope

The scheduled GitHub Actions scanner uses conservative launch defaults:

- `SCAN_LIMIT=30`
- `SCAN_SCOPES=mcp,extension,skill`
- `SCAN_SCOPE_LIMITS=mcp:5,extension:10,skill:15`
- `MAX_RUNTIME_MINUTES=10`

That means a normal run scans up to 5 MCP servers, 10 IDE extensions, and 15 AI
Skills. Each successful scan writes safe dashboard metadata to Supabase
`site_scans` immediately, so the public dashboard can update during the batch.

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
supabase/migrations/003_email_subscribers.sql
supabase/migrations/004_contact_messages.sql
```

This creates:

- `public.cg_scan_usage_windows`
- `public.cg_consume_scan_usage(...)`
- `public.site_content_overrides`
- `public.email_subscribers`
- `public.contact_messages`

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
