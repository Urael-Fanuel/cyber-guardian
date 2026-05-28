-- Email leads collected from the public threat alert signup form.

create table if not exists public.email_subscribers (
  email text primary key,
  source text not null default 'threat_alert_signup',
  ip_hint text,
  origin text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.email_subscribers enable row level security;
