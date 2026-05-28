-- Contact form messages from sales, support, enterprise, and security inquiries.

create table if not exists public.contact_messages (
  id bigserial primary key,
  kind text not null check (kind in ('sales', 'support', 'enterprise', 'security')),
  name text,
  email text not null,
  company text,
  message text not null,
  origin text,
  ip_hint text,
  created_at timestamptz not null default now()
);

alter table public.contact_messages enable row level security;
