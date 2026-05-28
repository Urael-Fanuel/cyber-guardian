-- Editable public copy for site and dashboard text.
-- Values are served by /api/content and can be changed only with the admin secret.

create table if not exists public.site_content_overrides (
  surface text not null check (surface in ('site', 'dashboard')),
  lang text not null,
  content_key text not null,
  content_value text not null,
  updated_at timestamptz not null default now(),
  primary key (surface, lang, content_key)
);

alter table public.site_content_overrides enable row level security;
