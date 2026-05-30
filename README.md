# Cyber-Guardian AI

Security scanner for MCP servers, AI Skills, and IDE extensions.

Live: https://cyberguardianscan.com

## What It Does

Cyber-Guardian AI helps developers and security teams review code before installing an MCP server, AI Skill, or IDE extension.

It checks 60 canonical threat families before a user decides whether to install or trust a component. Examples include:

- Tool poisoning and prompt injection
- Credential and API key access
- Reverse shells and OS command execution
- Suspicious install hooks
- Sensitive file access
- Obfuscation and exfiltration patterns
- Supply-chain risk indicators

## Architecture

| Layer | Technology |
| --- | --- |
| Frontend | Static HTML/CSS/JavaScript |
| API | Vercel Serverless Functions |
| AI analysis | Anthropic Claude |
| Database | Supabase |
| Rate limits | Supabase RPC plus server fallback |
| Batch scanner | Python scanner for GitHub, npm, MCP directories, Skills, and IDE extensions |

## Production Security Controls

- CORS allowlist via `ALLOWED_ORIGINS`
- Server-side free beta quota of 10 scans per month and rate limits via Supabase
- Global daily API cap
- Submitted code is not executed
- Canonical 60-family threat registry
- Definition for every threat family
- Static deterministic rule coverage for every family
- Static deterministic rules are merged with AI findings
- AI findings cannot downgrade high-confidence static findings
- No full submitted code is intentionally stored in Supabase

## Free Beta Access

Cyber-Guardian is currently in free beta. Visitors get 10 scans per month. Larger scan-volume requests are routed to `sales@cyberguardianscan.com`; public pricing is intentionally not shown during this learning phase.

## Local Checks

```bash
npm test
npm run check
python -m py_compile mcp_scanner.py
```

## Batch Scan Defaults

The GitHub Actions scanner runs once per hour with `SCAN_LIMIT=1` and rotates the scope by UTC hour: AI Skills, MCP servers, then IDE extensions. Scheduled runs also set `SCAN_OFFSET` so each hour advances through discovery results instead of rescanning the same top repository. Manual GitHub Actions runs still expose separate toggles and limits for each scan type. Each successful scan is saved immediately to Supabase `site_scans` and appears on the public dashboard without waiting for a batch to finish. Per-item and per-AI-call timeouts keep large IDE extension repositories from blocking the whole run.

## Required Production Environment

See `PRODUCTION.md` for Vercel and Supabase setup.

Core variables:

- `ANTHROPIC_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `ALLOWED_ORIGINS`
- `SCAN_USAGE_MODE=strict`

## Supabase Setup

Run this migration once in the Supabase SQL Editor:

```text
supabase/migrations/001_scan_usage_limits.sql
```

## Security Engine

See `SECURITY_ENGINE.md` for the rule model.

The scan engine currently enforces:

- exactly 60 canonical threat families;
- one definition per family;
- at least one deterministic static rule per family;
- AI semantic analysis across the same 60-family registry;
- test coverage that fails if a family, definition, or static rule is missing.

Every normalized scan response includes `threat_families_checked`, `threat_family_definitions`, and `coverage` metadata.

New scans also store scan intelligence for future recommendations: component type,
plain-English purpose, capabilities, use-case tags, source name/URL, and a code
hash. Run `supabase/migrations/005_site_scan_intelligence.sql` once so these
fields populate and the dashboard can show similar lower-risk alternatives.

## License

Apache 2.0
