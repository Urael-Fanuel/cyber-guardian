# Project Collaboration Instructions

The project owner is not a programmer and should not be expected to infer
technical steps independently.

When the owner needs to perform an action manually, always guide them one step
at a time. For every step, explain:

- exactly what to click, paste, run, or check
- why the step matters
- what result they should expect
- when they should stop and send a screenshot or the result back

Do not assume the owner understands programming concepts such as SQL,
migrations, deployments, environment variables, APIs, Git, Vercel, or Supabase.
If one of these terms is needed, explain it in simple language before asking
them to act.

Prefer short, clear Hebrew instructions for manual steps. Avoid giving many
steps at once unless the owner explicitly asks for a full checklist.

## Future API Split

Vercel Hobby currently limits the project to 12 Serverless Functions per
deployment. Because of that, some API endpoints were intentionally consolidated:

- account public config and account status live together in `api/account.js`
- admin leads and customer account management live together in `api/admin-data.js`

This consolidation is a deployment-limit workaround, not the preferred long-term
architecture. When the project moves to a plan/environment that allows more API
functions, split these back into separate focused endpoints for clearer
maintenance.

## Future Model Routing

Remember this product direction for future implementation: Cyber-Guardian
should eventually route each scan to the right analysis agent/model based on
the code type, risk, and complexity.

Examples:

- simple deterministic or low-risk scans can use cheaper/faster models
- complex MCP, skill, IDE extension, package, dependency, or GitHub Actions
  scans can use stronger models
- very complex or high-risk scans should be routed to the strongest available
  model, such as Anthropic Opus when appropriate, or a newer/better model when
  one is released

The goal is not to lock the product to one model. The long-term architecture
should support multiple scan modules and model providers, with clear routing
logic, cost control, and auditability.
