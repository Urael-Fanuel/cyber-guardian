# Cyber-Guardian MCP Server

Cyber-Guardian MCP lets an MCP-capable client ask Cyber-Guardian to scan pasted code before a user installs or trusts it.

It is designed for:

- Developers using Claude Desktop, Claude Code, Cursor, Windsurf, or other MCP clients.
- SaaS teams that want internal security checks for MCP servers, AI Skills, IDE extensions, GitHub Actions, packages, and dependencies.
- Companies that want a future bridge between their AI workspace and Cyber-Guardian scan results.

## What it does

The MCP server exposes five tools:

- `scan_code` - sends pasted code or config to Cyber-Guardian and returns a clear decision.
- `scan_github_source` - fetches current GitHub source through Cyber-Guardian and scans what is live now.
- `find_safer_alternative` - searches lower-risk historical alternatives and, when possible, verifies the candidate again before recommending it.
- `get_security_stats` - returns public scan counts by decision and component type.
- `service_info` - explains supported scan types, limits, and integration notes.

Supported scan scopes:

- `mcp`
- `skill`
- `extension`
- `github_action`
- `package`
- `dependency`

The server does not execute untrusted code locally. It sends the submitted content to the configured Cyber-Guardian scan API.

## Run locally

Requires Node.js 18 or newer.

From the Cyber-Guardian repository:

```bash
node mcp/cyberguardian-mcp-server.mjs
```

Default scan API:

```text
https://cyberguardianscan.com/api/scan
```

Optional environment variables:

```text
CG_API_BASE_URL=https://cyberguardianscan.com
CG_SCAN_API_URL=https://cyberguardianscan.com/api/scan
CG_STATS_API_URL=https://cyberguardianscan.com/api/site-stats
CG_OUTPUT_LANGUAGE=en
CG_MCP_TIMEOUT_MS=95000
CG_MCP_MAX_CODE_CHARS=50000
CG_SKIP_PERSIST=0
CG_ACCOUNT_TOKEN=
CG_ADMIN_BYPASS_SECRET=
```

Important:

- `CG_ADMIN_BYPASS_SECRET` is owner-only. Never give it to customers.
- `CG_ACCOUNT_TOKEN` is the future customer/account token path.
- `CG_SKIP_PERSIST=1` tells the scan API not to save scan metadata.

## Claude Desktop / Claude Code / Cursor style config

Use the example files in `mcp/client-config/`.

The command should point to Node.js, and the first argument should point to the absolute path of:

```text
mcp/cyberguardian-mcp-server.mjs
```

## Remote MCP for ChatGPT and Claude cloud

This repository now includes the local stdio MCP server.

Remote cloud connectors for ChatGPT or Claude require an HTTPS MCP deployment, customer authentication, and usually OAuth. That is the next product step and should be deployed separately from the current Vercel Hobby API limit, so it does not break the public scanner.

Recommended next architecture:

1. Keep this stdio MCP for local developer tools.
2. Create a dedicated remote MCP service later, for example on Cloudflare Workers, Fly.io, Render, Railway, or a Pro Vercel project.
3. Add OAuth/customer API keys.
4. Route remote MCP calls to the existing Cyber-Guardian scan API.
5. Enforce customer plan limits from Supabase.

## Example tool call

```json
{
  "code": "console.log('hello')",
  "scope": "skill",
  "output_language": "en",
  "persist_metadata": true
}
```

The response includes a plain-language report and structured JSON with:

- decision
- status
- threat score
- confidence
- findings
- recommendation
- code profile
- account quota, when available

Example safer-alternative call:

```json
{
  "scope": "skill",
  "purpose": "browse and summarize web documentation",
  "threats": "CREDENTIAL_THEFT,DATA_EXFILTRATION",
  "verify_now": true,
  "output_language": "en"
}
```

When `verify_now` is true and the candidate has a GitHub source URL, the MCP server asks Cyber-Guardian to fetch the current source and scan it again before returning the recommendation.
