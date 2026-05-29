-- Enriched scan intelligence for recommendations and clearer dashboard decisions.
-- Run this once in the Supabase SQL Editor.

alter table public.site_scans
  add column if not exists source_name text,
  add column if not exists source_url text,
  add column if not exists source_owner text,
  add column if not exists code_hash text,
  add column if not exists code_purpose text,
  add column if not exists component_type text,
  add column if not exists capabilities text[] not null default '{}',
  add column if not exists use_case_tags text[] not null default '{}';

create index if not exists site_scans_scope_scanned_at_idx
  on public.site_scans (scope, scanned_at desc);

create index if not exists site_scans_component_type_idx
  on public.site_scans (component_type);

create index if not exists site_scans_use_case_tags_gin_idx
  on public.site_scans using gin (use_case_tags);

create index if not exists site_scans_capabilities_gin_idx
  on public.site_scans using gin (capabilities);
