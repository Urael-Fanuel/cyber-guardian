-- Internal orchestrator specialist runs for Cyber-Guardian scans.
-- Run once in the Supabase SQL Editor after 011_scan_evidence.sql.
-- This table stores internal evidence metadata. It is not public website copy.

create table if not exists public.cg_scan_agent_runs (
  id uuid primary key default gen_random_uuid(),
  scan_run_id uuid,
  scope text not null,
  source_name text,
  source_url text,
  source_owner text,
  code_hash text,
  agent_key text not null,
  agent_name text,
  focus text,
  checked boolean not null default true,
  finding_count integer not null default 0 check (finding_count >= 0),
  max_severity text not null default 'NONE',
  confidence numeric(4,3) not null default 0 check (confidence >= 0 and confidence <= 1),
  needs_sandbox boolean not null default false,
  evidence_ids text[] not null default '{}',
  summary text,
  created_at timestamptz not null default now()
);

create index if not exists cg_scan_agent_runs_scan_idx
  on public.cg_scan_agent_runs (scan_run_id);

create index if not exists cg_scan_agent_runs_agent_idx
  on public.cg_scan_agent_runs (agent_key, created_at desc);

create index if not exists cg_scan_agent_runs_source_idx
  on public.cg_scan_agent_runs (source_url);

create index if not exists cg_scan_agent_runs_code_hash_idx
  on public.cg_scan_agent_runs (code_hash);

alter table public.cg_scan_agent_runs enable row level security;
