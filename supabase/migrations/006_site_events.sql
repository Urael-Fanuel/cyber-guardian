-- Product analytics events for Cyber-Guardian.
-- Stores anonymous usage events only. Raw IP addresses are not stored.

create table if not exists public.site_events (
  id uuid primary key default gen_random_uuid(),
  event_name text not null,
  page_path text,
  referrer text,
  scan_scope text,
  country text,
  region text,
  city text,
  user_agent text,
  visitor_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.site_events enable row level security;

create index if not exists site_events_created_at_idx
  on public.site_events (created_at desc);

create index if not exists site_events_event_name_created_at_idx
  on public.site_events (event_name, created_at desc);

create index if not exists site_events_country_idx
  on public.site_events (country);

create index if not exists site_events_scan_scope_idx
  on public.site_events (scan_scope);

create index if not exists site_events_metadata_gin_idx
  on public.site_events using gin (metadata);
