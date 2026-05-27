-- Cyber-Guardian scan usage limits.
-- Run this file once in the Supabase SQL Editor.

create table if not exists public.cg_scan_usage_windows (
  usage_key text primary key,
  usage_count integer not null default 0 check (usage_count >= 0),
  expires_at timestamptz not null,
  updated_at timestamptz not null default now()
);

create index if not exists cg_scan_usage_windows_expires_at_idx
  on public.cg_scan_usage_windows (expires_at);

alter table public.cg_scan_usage_windows enable row level security;

drop policy if exists "service role manages scan usage" on public.cg_scan_usage_windows;
create policy "service role manages scan usage"
  on public.cg_scan_usage_windows
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

create or replace function public.cg_consume_scan_usage(
  p_ip_hash text,
  p_minute_key text,
  p_hour_key text,
  p_day_key text,
  p_month_key text,
  p_max_minute integer,
  p_max_hour integer,
  p_max_day integer,
  p_max_month integer
)
returns table (
  ok boolean,
  reason text,
  retry_after integer,
  quota_used integer,
  quota_limit integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_minute_key text := 'scan:minute:' || p_ip_hash || ':' || p_minute_key;
  v_hour_key text := 'scan:hour:' || p_ip_hash || ':' || p_hour_key;
  v_day_key text := 'scan:day:global:' || p_day_key;
  v_month_key text := 'scan:month:' || p_ip_hash || ':' || p_month_key;
  v_minute_count integer;
  v_hour_count integer;
  v_day_count integer;
  v_month_count integer;
begin
  perform pg_advisory_xact_lock(hashtext('cg_scan_usage:' || p_ip_hash));

  delete from public.cg_scan_usage_windows
  where expires_at < now()
  and random() < 0.02;

  select usage_count into v_minute_count from public.cg_scan_usage_windows where usage_key = v_minute_key;
  select usage_count into v_hour_count from public.cg_scan_usage_windows where usage_key = v_hour_key;
  select usage_count into v_day_count from public.cg_scan_usage_windows where usage_key = v_day_key;
  select usage_count into v_month_count from public.cg_scan_usage_windows where usage_key = v_month_key;

  v_minute_count := coalesce(v_minute_count, 0);
  v_hour_count := coalesce(v_hour_count, 0);
  v_day_count := coalesce(v_day_count, 0);
  v_month_count := coalesce(v_month_count, 0);

  if v_minute_count >= p_max_minute then
    return query select false, 'minute_limit', 60, v_month_count, p_max_month;
    return;
  end if;

  if v_hour_count >= p_max_hour then
    return query select false, 'hour_limit', 3600, v_month_count, p_max_month;
    return;
  end if;

  if v_day_count >= p_max_day then
    return query select false, 'day_limit', 86400, v_month_count, p_max_month;
    return;
  end if;

  if v_month_count >= p_max_month then
    return query select false, 'month_limit', 86400, v_month_count, p_max_month;
    return;
  end if;

  insert into public.cg_scan_usage_windows (usage_key, usage_count, expires_at, updated_at)
  values
    (v_minute_key, 1, now() + interval '2 minutes', now()),
    (v_hour_key, 1, now() + interval '2 hours', now()),
    (v_day_key, 1, now() + interval '2 days', now()),
    (v_month_key, 1, date_trunc('month', now()) + interval '2 months', now())
  on conflict (usage_key) do update
    set usage_count = public.cg_scan_usage_windows.usage_count + 1,
        updated_at = now();

  return query select true, null::text, 0, v_month_count + 1, p_max_month;
end;
$$;

revoke all on function public.cg_consume_scan_usage(text, text, text, text, text, integer, integer, integer, integer)
  from public, anon, authenticated;
grant execute on function public.cg_consume_scan_usage(text, text, text, text, text, integer, integer, integer, integer)
  to service_role;
