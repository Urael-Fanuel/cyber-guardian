-- Separate owner activity from public visitor analytics.
-- Existing rows remain public because old events did not carry trusted owner auth.

alter table public.site_events
  add column if not exists actor text not null default 'public';

alter table public.site_events
  drop constraint if exists site_events_actor_check;

alter table public.site_events
  add constraint site_events_actor_check
  check (actor in ('public', 'owner'));

create index if not exists site_events_actor_created_at_idx
  on public.site_events (actor, created_at desc);

create index if not exists site_events_actor_country_idx
  on public.site_events (actor, country);
