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
CG_ADMIN_USERNAME=admin
CG_ADMIN_PASSWORD=generate-a-different-long-password
SITE_URL=https://cyberguardianscan.com

# Optional later, when payment is enabled:
# STRIPE_SECRET_KEY=sk_live_...
# STRIPE_PRICE_PRO=price_...
# STRIPE_PRICE_TEAM=price_...
# STRIPE_PRICE_BUSINESS=price_...

RESEND_API_KEY=re_...
SUBSCRIBE_NOTIFY_TO=sales@cyberguardianscan.com
CONTACT_SALES_TO=sales@cyberguardianscan.com
CONTACT_SUPPORT_TO=support@cyberguardianscan.com
EMAIL_FROM=Cyber-Guardian <notifications@cyberguardianscan.com>

SCAN_USAGE_MODE=strict
SCAN_MAX_REQUESTS_PER_MINUTE=5
SCAN_MAX_REQUESTS_PER_HOUR=20
SCAN_MAX_FREE_SCANS_PER_MONTH=10
SCAN_MAX_API_CALLS_PER_DAY=5000
SCAN_MAX_INPUT_SIZE_CHARS=50000
SCAN_MIN_INPUT_SIZE_CHARS=5
SCAN_CACHE_TTL_SECONDS=3600
```

Use `SCAN_USAGE_MODE=strict` in production after the Supabase SQL migration has been run.
Use `SCAN_USAGE_MODE=fallback` only during setup or local development.

## Free Beta Access

Paid checkout is intentionally disabled during the beta launch. The public site
offers 10 free scans per month and routes larger-volume inquiries to
`sales@cyberguardianscan.com`. Public pricing is intentionally not shown during
this learning phase.

When the business and payment setup are ready, create recurring monthly prices
in Stripe and copy their price IDs into the relevant variables, for example:

- `STRIPE_PRICE_PRO`
- `STRIPE_PRICE_TEAM`
- `STRIPE_PRICE_BUSINESS`

The existing `/api/create-checkout-session` endpoint can create a Stripe Checkout
subscription session once public payment buttons are enabled. Keep
`STRIPE_SECRET_KEY` server-side only in Vercel environment variables.

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

`/content-admin.html` provides a username/password login for the site owner.
Set `CG_ADMIN_USERNAME` and `CG_ADMIN_PASSWORD` in Vercel. The password is
exchanged for a signed 12-hour admin token and is not stored in the browser.

The same signed admin token lets the site owner run unlimited scans without
changing the public 10-scan monthly limit for normal visitors.

`CG_ADMIN_BYPASS_SECRET` is still supported for GitHub Actions and emergency
manual bypasses. Keep it private.

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
- `SCAN_SCOPES=skill,mcp,extension`
- `SCAN_SCOPE_LIMITS=skill:15,mcp:10,extension:5`
- `MAX_RUNTIME_MINUTES=10`

That means a normal run scans up to 15 AI Skills, 10 MCP servers, and 5 IDE
extensions. Manual GitHub Actions runs expose separate toggles and limits for
each scan type. Each successful scan writes safe dashboard metadata to Supabase
`site_scans` immediately, so the public dashboard can update during the batch.

Run `supabase/migrations/005_site_scan_intelligence.sql` to enrich `site_scans`
with purpose, capabilities, source metadata, and use-case tags. These fields power
the dashboard explanation of what each scanned component does and enable similar
lower-risk recommendations.

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
- `SCAN_MAX_FREE_SCANS_PER_MONTH=10`
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
