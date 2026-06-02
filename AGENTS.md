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
