-- Strategic moat tables for Cyber-Guardian.
-- Run once in the Supabase SQL Editor.
-- These tables are service-role managed. Public users do not get direct table access.

create table if not exists public.cg_threat_intel_reports (
  id uuid primary key default gen_random_uuid(),
  report_source text not null default 'web',
  scope text,
  source_name text,
  source_url text,
  source_hash text,
  event_type text not null,
  severity text not null default 'medium',
  behavior text not null,
  indicators jsonb not null default '{}'::jsonb,
  country text,
  region text,
  city text,
  user_agent text,
  visitor_id text,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create index if not exists cg_threat_intel_reports_created_idx
  on public.cg_threat_intel_reports (created_at desc);

create index if not exists cg_threat_intel_reports_scope_idx
  on public.cg_threat_intel_reports (scope);

create index if not exists cg_threat_intel_reports_event_type_idx
  on public.cg_threat_intel_reports (event_type);

create index if not exists cg_threat_intel_reports_indicators_gin_idx
  on public.cg_threat_intel_reports using gin (indicators);

create table if not exists public.cg_registry_entries (
  id uuid primary key default gen_random_uuid(),
  scope text not null,
  source_name text not null,
  source_url text not null unique,
  source_owner text,
  creator_name text,
  creator_verified boolean not null default false,
  verified_creator_level text,
  trust_score integer not null default 50 check (trust_score between 0 and 100),
  trust_status text not null default 'unverified',
  scan_count integer not null default 0,
  clean_scan_count integer not null default 0,
  review_scan_count integer not null default 0,
  blocked_scan_count integer not null default 0,
  user_reports_count integer not null default 0,
  last_scan_status text,
  last_threat_score integer,
  last_seen_at timestamptz,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists cg_registry_entries_scope_score_idx
  on public.cg_registry_entries (scope, trust_score desc);

create index if not exists cg_registry_entries_owner_idx
  on public.cg_registry_entries (source_owner);

create table if not exists public.cg_wrapper_requests (
  id uuid primary key default gen_random_uuid(),
  request_source text not null default 'web_scan_result',
  scope text,
  source_name text,
  source_url text,
  decision text,
  threat_score integer,
  threat_families text[] not null default '{}',
  code_purpose text,
  requested_controls text[] not null default '{}',
  wrapper_status text not null default 'requested',
  contact_email text,
  visitor_id text,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists cg_wrapper_requests_created_idx
  on public.cg_wrapper_requests (created_at desc);

create index if not exists cg_wrapper_requests_status_idx
  on public.cg_wrapper_requests (wrapper_status);

create table if not exists public.cg_runtime_policy_templates (
  id uuid primary key default gen_random_uuid(),
  scope text not null,
  template_name text not null,
  description text not null,
  default_deny boolean not null default true,
  allowed_file_patterns text[] not null default '{}',
  blocked_file_patterns text[] not null default '{}',
  allowed_network_hosts text[] not null default '{}',
  blocked_network_hosts text[] not null default '{}',
  allowed_commands text[] not null default '{}',
  blocked_commands text[] not null default '{}',
  status text not null default 'draft',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.cg_threat_intel_reports enable row level security;
alter table public.cg_registry_entries enable row level security;
alter table public.cg_wrapper_requests enable row level security;
alter table public.cg_runtime_policy_templates enable row level security;

