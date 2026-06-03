-- Evidence Aggregator for Cyber-Guardian scan findings.
-- Run once in the Supabase SQL Editor.
-- This table stores each concrete finding as a durable evidence item.

alter table public.site_scans
  add column if not exists scan_run_id uuid;

create table if not exists public.cg_scan_evidence (
  id uuid primary key default gen_random_uuid(),
  scan_run_id uuid,
  scope text not null,
  status text not null,
  decision text,
  risk_type text,
  source_name text,
  source_url text,
  source_owner text,
  code_hash text,
  code_purpose text,
  component_type text,
  evidence_id text,
  family text not null default 'UNCLASSIFIED',
  severity text not null default 'MEDIUM',
  confidence numeric(4,3) not null default 0 check (confidence >= 0 and confidence <= 1),
  evidence text,
  line_hint text,
  plain_explanation text,
  impact_key text,
  user_impact text,
  fix_key text,
  fix_guidance text,
  created_at timestamptz not null default now()
);

create index if not exists cg_scan_evidence_run_idx
  on public.cg_scan_evidence (scan_run_id);

create index if not exists cg_scan_evidence_created_idx
  on public.cg_scan_evidence (created_at desc);

create index if not exists cg_scan_evidence_scope_family_idx
  on public.cg_scan_evidence (scope, family);

create index if not exists cg_scan_evidence_severity_idx
  on public.cg_scan_evidence (severity);

create index if not exists cg_scan_evidence_source_url_idx
  on public.cg_scan_evidence (source_url);

create index if not exists cg_scan_evidence_code_hash_idx
  on public.cg_scan_evidence (code_hash);

alter table public.cg_scan_evidence enable row level security;
