# Cyber-Guardian Remote MCP

This folder contains a Cloudflare Worker implementation for a remote MCP endpoint.

Endpoint shape:

```text
https://mcp.cyberguardianscan.com/mcp
```

Health check:

```text
https://mcp.cyberguardianscan.com/health
```

## What It Does

The remote MCP exposes:

- `scan_code`
- `find_safer_alternative`
- `get_security_stats`
- `service_info`

It does not execute submitted code. It routes scan requests to the existing
Cyber-Guardian scan API and returns MCP-compatible JSON-RPC responses.

## Why Cloudflare Worker

Do not add this as another Vercel Serverless Function in the current app. The
project has already hit the Vercel Hobby function limit. A separate Worker keeps
the public scanner stable while the remote MCP becomes its own product surface.

## Setup Steps

1. Install Wrangler locally only when you are ready to deploy:

```bash
npm install -g wrangler
```

2. Copy the example config:

```bash
copy remote-mcp\wrangler.toml.example remote-mcp\wrangler.toml
```

3. Log in to Cloudflare:

```bash
wrangler login
```

4. Deploy from this folder:

```bash
cd remote-mcp
wrangler deploy
```

5. Add a custom domain in Cloudflare Workers:

```text
mcp.cyberguardianscan.com
```

6. Optional private beta protection:

```bash
wrangler secret put CG_REMOTE_MCP_SHARED_TOKEN
```

If this secret is configured, remote clients must send:

```text
Authorization: Bearer <your-token>
```

## Important Product Notes

This is the first remote MCP service layer. For paid customer use, the next step
is account-grade authentication:

- OAuth for Claude/OpenAI cloud connectors when required.
- Cyber-Guardian account API tokens mapped to Supabase plan limits.
- Audit logs per customer account.
- Separate enterprise policies.

Do not give `CG_ADMIN_BYPASS_SECRET` to customers.
