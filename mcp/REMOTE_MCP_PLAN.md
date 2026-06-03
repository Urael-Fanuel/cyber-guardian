# Remote MCP Product Plan

The local MCP server is ready for MCP clients that launch a local process.

For ChatGPT apps/connectors, Claude custom connectors, and enterprise SaaS embedding, Cyber-Guardian needs a remote MCP service.

## Why not place it directly in the current Vercel Hobby app?

The current project already uses many Serverless Functions and previously hit the Vercel Hobby limit. A remote MCP endpoint would add more server functions and session/auth complexity. It should be separated when we move to a paid or dedicated hosting plan.

## Minimum remote version

1. HTTPS endpoint: `https://mcp.cyberguardianscan.com/mcp`
2. Tool: `scan_code`
3. Tool: `service_info`
4. Customer auth: OAuth or API key mapped to Supabase account plans
5. Quota enforcement: Supabase `cg_user_subscriptions` and `cg_user_scan_usage`
6. Audit metadata: source name, scope, risk decision, threat families, timestamp

## Enterprise version

1. Organization accounts and seats
2. Per-team policies: allowed scan scopes, metadata retention, allowed domains
3. Private scan mode
4. Runtime MCP firewall agent
5. Secure wrapper generation workflow
6. Verified alternative search and rescan
7. SIEM/webhook export

## Product positioning

The remote MCP is not only a scanner. It becomes the Cyber-Guardian security layer inside the customer's AI workflow:

- Before install: scan pasted MCP/Skill/extension/package code.
- During work: future runtime policy enforcement.
- After detection: safer alternatives and secure-wrapper requests.
- For leadership: dashboard, analytics, and proof of review.
