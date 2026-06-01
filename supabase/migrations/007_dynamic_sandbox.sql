-- Store optional dynamic sandbox evidence attached to each scan.
-- The web app never executes untrusted code inside Vercel; this column records
-- evidence returned by a separate isolated sandbox runner/provider when enabled.

alter table public.site_scans
  add column if not exists dynamic_sandbox jsonb not null default '{}'::jsonb;

create index if not exists site_scans_dynamic_sandbox_gin_idx
  on public.site_scans using gin (dynamic_sandbox);
