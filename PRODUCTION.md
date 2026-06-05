# Cyber-Guardian Production Runbook

This file lists the minimum production setup for Cyber-Guardian.

## Required Vercel Environment Variables

Set these in Vercel Project Settings -> Environment Variables:

```text
ANTHROPIC_API_KEY=...
ANTHROPIC_MODEL=claude-sonnet-4-6
ANTHROPIC_FALLBACK_MODELS=claude-haiku-4-5-20251001,claude-sonnet-4-20250514
ANTHROPIC_MAX_TOKENS=2500
ANTHROPIC_TIMEOUT_MS=60000

SUPABASE_URL=...
SUPABASE_SERVICE_KEY=...
SUPABASE_ANON_KEY=...

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

# Optional dynamic sandbox runner/provider:
DYNAMIC_SANDBOX_ENABLED=false
DYNAMIC_SANDBOX_WEBHOOK_URL=https://your-isolated-runner.example.com/scan
DYNAMIC_SANDBOX_API_KEY=...
DYNAMIC_SANDBOX_PROVIDER=external-isolated-runner
DYNAMIC_SANDBOX_TIMEOUT_MS=4500
DYNAMIC_SANDBOX_MIN_SCORE=0
DYNAMIC_SANDBOX_SCOPES=mcp,skill,extension,github_action,package,dependency
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

## Account Plans

Run `supabase/migrations/009_user_accounts_and_quotas.sql` in Supabase to enable
customer accounts, monthly plan quotas, and account-level scan usage.

The public site uses Supabase Auth email/password login. A signed-in account sends
its Supabase session token to `/api/scan`, and the server consumes that user's
monthly scan quota instead of the anonymous visitor quota.

Until Stripe webhooks are connected, customer access is assigned manually in
`/content-admin.html` after admin login. Use the "Customer accounts and scan
plans" panel to create/update a customer email, set an initial password for new
users, choose the plan, and set the access period.

Required setup:

- Add `SUPABASE_ANON_KEY` in Vercel. This is the public Supabase anon key, not the
  service key.
- Keep `SUPABASE_SERVICE_KEY` server-side only.
- Enable Supabase Auth email/password sign-in in the Supabase dashboard.
- Configure Supabase Auth custom SMTP through Resend for production auth emails:
  - Sender email: `notifications@cyberguardianscan.com`
  - Sender name: `Cyber Guardian Scan`
  - Host: `smtp.resend.com`
  - Port: `587`
  - Username: `resend`
  - Password: a Resend API key with sending access for `cyberguardianscan.com`.
  - Never commit the Resend API key or SMTP password to GitHub.
- Run migration `009_user_accounts_and_quotas.sql`.

## Email Lead Notifications

The threat-alert signup form posts to `/api/subscribe`. Each valid email is saved
to Supabase `email_subscribers` and, when `RESEND_API_KEY` is configured, a lead
notification is sent to `SUBSCRIBE_NOTIFY_TO` (default:
`sales@cyberguardianscan.com`).

Resend requires an API key and a verified sending domain before production email
delivery. Keep `RESEND_API_KEY` server-side only in Vercel environment variables.
Recent subscribers are also visible in `/content-admin.html` after admin login.

## Contact Form

The contact buttons link to `/contact.html` instead of `mailto:` links, so visitors
stay inside the site instead of opening Outlook/Microsoft Mail. The form posts to
`/api/contact`, saves messages in Supabase `contact_messages`, and sends email
notifications through Resend.

Sales and enterprise requests go to `CONTACT_SALES_TO`; support and security
requests go to `CONTACT_SUPPORT_TO`.
Recent contact messages are also visible in `/content-admin.html` after admin
login.

## Product Analytics

Run `supabase/migrations/006_site_events.sql` in Supabase to enable anonymous
product analytics. The site then stores page views, scan starts, completed scans,
failed scans, Sales clicks, contact form submissions, and email signups in
`site_events`.

Raw IP addresses are not stored. Country, region, and city are taken from Vercel
geo headers when available. The detailed analytics endpoint requires the signed
admin token, so business metrics are visible only after the owner logs in at
`/content-admin.html`. The public dashboard must not load or render product
analytics.

The private admin analytics view aggregates public usage by country, scan type,
scan status, score bucket, contact intent, email signup, selected language,
device/browser class, referrer domain, and top pages. These fields are stored as
anonymous event metadata in `site_events.metadata`, so this reporting expansion
does not require an additional database migration.
Run `supabase/migrations/008_site_event_actor.sql` to separate owner activity
from public visitor analytics. The separation is trusted only when events include
a valid signed admin token; older events may still be mixed.

## Dynamic Sandbox

The Vercel scan API must not execute untrusted user code directly. For dynamic
behavior analysis, connect a separate hardened runner/provider and set
`DYNAMIC_SANDBOX_ENABLED=true` with `DYNAMIC_SANDBOX_WEBHOOK_URL`.

The runner endpoint receives the submitted code plus static scan context and
should return JSON with fields such as `status`, `verdict`, `threat_score`,
`summary`, `signals`, and `report_url`. Returned evidence is attached to the scan
response and saved in Supabase `site_scans.dynamic_sandbox`.

The runner should treat the built-in `fuzzing_profile` as a minimum test plan. It
should generate rare input edge cases, watch file integrity events, record dynamic
library loads, detect sensitive-file staging, record process/shell execution, and
capture network/DNS destinations. The runner should fail closed: suspicious
runtime behavior may raise a scan from safe/review to critical, but it must never
downgrade deterministic findings.

Run `supabase/migrations/007_dynamic_sandbox.sql` before enabling the runner in
production.

## Developer Bypass

`/content-admin.html` provides a username/password login for the site owner.
Set `CG_ADMIN_USERNAME` and `CG_ADMIN_PASSWORD` in Vercel. The password is
exchanged for a signed 30-day admin token and is not stored in the browser.

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

The scheduled GitHub Actions scanner spreads discovery throughout the day:

- Runs once per hour.
- Scheduled runs use `SCAN_LIMIT=1`.
- Scope rotates by UTC hour: `skill`, `mcp`, `extension`, then repeats.
- Scheduled runs set `SCAN_OFFSET` from the day/hour so each run advances through
  discovery results instead of repeatedly scanning the same top repository.
- `MAX_RUNTIME_MINUTES=10`
- `MAX_ITEM_SECONDS=45`
- `MAX_CG_SCAN_SECONDS=45`

That means the public dashboard receives a steadier stream of scan results during
the day instead of one large daily batch. Manual GitHub Actions runs still expose
separate toggles and limits for each scan type. Each successful scan writes safe
dashboard metadata to Supabase `site_scans` immediately, so the public dashboard
can update during the run.
Large IDE extension repositories are capped by file count, byte count, and
per-item timeouts so one repository cannot stall the entire run.

Run `supabase/migrations/005_site_scan_intelligence.sql` to enrich `site_scans`
with purpose, capabilities, source metadata, and use-case tags. These fields power
the dashboard explanation of what each scanned component does and enable similar
lower-risk recommendations.

## MCP Integration

The repository includes a local stdio MCP server at
`mcp/cyberguardian-mcp-server.mjs`.

Run locally:

```bash
npm run mcp:stdio
```

This local MCP server calls the existing Cyber-Guardian APIs and exposes:

- `scan_code`
- `scan_github_source`
- `find_safer_alternative`
- `get_security_stats`
- `service_info`

`find_safer_alternative` is deliberately conservative: historical alternatives are
not treated as trustworthy forever. When the candidate has a GitHub source URL,
the MCP server can fetch the current source and rescan it before returning the
recommendation.

Keep `CG_ADMIN_BYPASS_SECRET` owner-only. Customer usage should move to account
tokens/API keys, not the admin bypass secret.

Remote MCP for ChatGPT apps/connectors, Claude cloud connectors, and enterprise
SaaS embedding should be deployed as a separate HTTPS service with OAuth or
customer API keys. Do not add it as another Serverless Function to the current
Hobby deployment because this project has already hit the Vercel Hobby function
limit. See `mcp/REMOTE_MCP_PLAN.md`.

The repository also includes a first Cloudflare Worker implementation in
`remote-mcp/`. Use that path for the initial HTTPS MCP beta instead of adding
more functions to this Vercel project.

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
supabase/migrations/005_site_scan_intelligence.sql
supabase/migrations/006_site_events.sql
supabase/migrations/007_dynamic_sandbox.sql
supabase/migrations/008_site_event_actor.sql
supabase/migrations/009_user_accounts_and_quotas.sql
```

This creates:

- `public.cg_scan_usage_windows`
- `public.cg_consume_scan_usage(...)`
- `public.site_content_overrides`
- `public.email_subscribers`
- `public.contact_messages`
- `public.site_events`
- `public.site_events.actor`
- `public.site_scans.dynamic_sandbox`
- `public.cg_account_plans`
- `public.cg_user_subscriptions`
- `public.cg_user_scan_usage`
- `public.cg_consume_user_scan_usage(...)`

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
- Confirm Vercel does not execute submitted code; dynamic analysis uses only the isolated sandbox runner/provider.
- Confirm privacy/terms say whether user-submitted code may be sent to a third-party AI provider.
- Confirm privacy/terms say whether user-submitted code may be sent to a third-party sandbox provider.

## Current Known Limits

- Anonymous visitor quota is IP-based; signed-in customer quotas are account-based.
- Stripe payment webhooks are not connected yet, so paid plan assignment is manual
  in the admin page.
- Enterprise/private scanning should add API keys and org-level quotas.
- The AI verdict should be supported by deterministic rules for stronger auditability.
- Dynamic sandbox execution requires a separate isolated runner/provider; it is not performed inside Vercel.
