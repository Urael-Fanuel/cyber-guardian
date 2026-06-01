-- Account-based plans and monthly scan quotas.
-- This is the foundation for paid plans. Stripe can update these tables later.

create table if not exists public.cg_account_plans (
  plan_code text primary key,
  display_name text not null,
  monthly_scan_limit integer not null check (monthly_scan_limit >= 0),
  price_usd numeric(10,2),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

insert into public.cg_account_plans (plan_code, display_name, monthly_scan_limit, price_usd)
values
  ('free', 'Free', 10, 0),
  ('personal', 'Personal', 100, 9),
  ('team', 'Team', 500, 29),
  ('business', 'Business', 2000, 99),
  ('enterprise', 'Enterprise', 10000, null)
on conflict (plan_code) do update
set display_name = excluded.display_name,
    monthly_scan_limit = excluded.monthly_scan_limit,
    price_usd = excluded.price_usd,
    updated_at = now();

create table if not exists public.cg_user_subscriptions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  plan_code text not null references public.cg_account_plans(plan_code) default 'free',
  status text not null default 'active'
    check (status in ('active', 'trialing', 'past_due', 'canceled', 'unpaid', 'manual')),
  current_period_start timestamptz not null default date_trunc('month', now()),
  current_period_end timestamptz not null default (date_trunc('month', now()) + interval '1 month'),
  stripe_customer_id text,
  stripe_subscription_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.cg_user_scan_usage (
  user_id uuid not null references auth.users(id) on delete cascade,
  month_key text not null,
  usage_count integer not null default 0 check (usage_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (user_id, month_key)
);

alter table public.cg_account_plans enable row level security;
alter table public.cg_user_subscriptions enable row level security;
alter table public.cg_user_scan_usage enable row level security;

create index if not exists cg_user_subscriptions_plan_idx
  on public.cg_user_subscriptions (plan_code);

create index if not exists cg_user_scan_usage_month_idx
  on public.cg_user_scan_usage (month_key);

create or replace function public.cg_consume_user_scan_usage(
  p_user_id uuid,
  p_month_key text,
  p_plan_code text,
  p_quota_limit integer
)
returns table (
  ok boolean,
  reason text,
  quota_used integer,
  quota_limit integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_current integer := 0;
  v_next integer := 0;
begin
  if p_user_id is null or coalesce(p_month_key, '') = '' then
    return query select false, 'invalid_account'::text, 0, greatest(coalesce(p_quota_limit, 0), 0);
    return;
  end if;

  if coalesce(p_quota_limit, 0) <= 0 then
    return query select false, 'quota_limit'::text, 0, 0;
    return;
  end if;

  perform pg_advisory_xact_lock(hashtext('cg_user_scan_usage:' || p_user_id::text || ':' || p_month_key));

  select usage_count into v_current
  from public.cg_user_scan_usage
  where user_id = p_user_id and month_key = p_month_key;

  v_current := coalesce(v_current, 0);

  if v_current >= p_quota_limit then
    return query select false, 'month_limit'::text, v_current, p_quota_limit;
    return;
  end if;

  v_next := v_current + 1;

  insert into public.cg_user_scan_usage (user_id, month_key, usage_count, updated_at)
  values (p_user_id, p_month_key, v_next, now())
  on conflict (user_id, month_key) do update
    set usage_count = v_next,
        updated_at = now();

  return query select true, 'ok'::text, v_next, p_quota_limit;
end;
$$;

revoke all on function public.cg_consume_user_scan_usage(uuid, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.cg_consume_user_scan_usage(uuid, text, text, integer)
  to service_role;
