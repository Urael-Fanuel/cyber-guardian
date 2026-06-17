-- Separate partial / inconclusive scans from public dashboard review stats.
-- Run once in the Supabase SQL Editor.

alter table public.site_scans
  add column if not exists scan_coverage jsonb not null default '{}'::jsonb,
  add column if not exists coverage_capped boolean not null default false,
  add column if not exists decision text,
  add column if not exists risk_type text;

create index if not exists site_scans_coverage_capped_idx
  on public.site_scans (coverage_capped);

create index if not exists site_scans_decision_idx
  on public.site_scans (decision);

create index if not exists site_scans_risk_type_idx
  on public.site_scans (risk_type);

-- Backfill old "needs review" rows that had no concrete threat evidence.
-- These should not inflate the public "Security Review" dashboard count.
update public.site_scans
set
  decision = coalesce(decision, 'security_review'),
  risk_type = 'insufficient_context'
where status in ('STATUS_MODERATE', 'STATUS_AMBIGUOUS')
  and coalesce(threat_count, 0) = 0
  and nullif(trim(coalesce(threats_summary, '')), '') is null
  and coalesce(risk_type, '') <> 'security_weakness';
