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

## Future Paid Alternative Discovery

Remember this product direction: when a scan returns "do not install",
"fix before use", or another warning, the product should eventually offer a
paid "Find a safer alternative" workflow.

Long-term behavior:

- search the existing Supabase scan history for similar lower-risk code first
- if no reliable match exists, use external discovery systems such as Apify,
  repository search, package registries, and other vetted sources
- scan candidate alternatives before recommending them
- never recommend an alternative solely because it was clean in a historical
  scan; historical scans are candidates only
- before showing an alternative as safe, fetch the current source and rescan it
  because attackers may publish clean code first and later replace it with
  malicious behavior
- show one strong recommended alternative, not a confusing list
- make it clear that alternatives still require review and rescanning
- support paid team/company/enterprise plans and monthly credits
- consider future partnerships with authors who publish clean, reviewed MCPs,
  Skills, IDE extensions, packages, and workflows

This feature should be treated as a premium business value: companies do not
only want warnings; they want a safe replacement path.

## Strategic Moat Roadmap

Remember this strategic direction: Cyber-Guardian should become more than a
scanner. It should become a defensible trust network for MCPs, AI Skills, IDE
extensions, GitHub Actions, packages, and dependencies.

Prioritized moat pillars:

- decentralized threat intelligence web: future MCP/IDE agents report
  anonymized runtime anomalies such as unexpected `.env` access, network
  callbacks, blocked permission attempts, and suspicious shell execution
- Trust Score & Registry: scanned sources build dynamic reputation from scan
  history, creator verification, recent behavior, and community reports
- autonomous sandbox fuzzing: when an isolated runner is connected, scan
  payloads include honeytokens and attack objectives for active boundary tests
- Secure Wrapper workflow: when there is no clean alternative, queue a wrapper
  request that can generate a controlled policy layer around the risky tool
- Runtime MCP Firewall: future local agent should enforce permissions during
  live use, then report policy blocks back into threat intelligence

Do not overclaim these features publicly. Show them as active foundations,
beta workflows, or future agent capabilities unless the local agent/runner is
actually connected and verified.
