-- Run this ONCE in the Supabase SQL editor on an existing PrintFlow database.
-- It closes the public read/write access and adds what the new backend needs.
-- Safe to run more than once.

-- 1. Remove the public policies that let anyone read and edit every order
drop policy if exists "Allow public insert" on public.orders;
drop policy if exists "Allow public select" on public.orders;
drop policy if exists "Allow public update" on public.orders;
alter table public.orders enable row level security;

-- 2. Stop broadcasting orders over Realtime (anyone with the public key could listen)
do $$
begin
  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'orders'
  ) then
    alter publication supabase_realtime drop table public.orders;
  end if;
end $$;

-- 3. New columns used by the backend
alter table public.orders add column if not exists files jsonb not null default '[]'::jsonb;
alter table public.orders add column if not exists razorpay_order_id text;
alter table public.orders add column if not exists paid_at timestamp with time zone;
alter table public.orders alter column utr_number set default '';
alter table public.orders alter column order_status set default 'Awaiting Payment';

create index if not exists orders_created_at_idx on public.orders (created_at desc);
create index if not exists orders_utr_idx on public.orders (utr_number) where utr_number <> '';

-- 4. Shop settings (name, UPI ID, rates) now live in the database, edited by the owner via the backend
create table if not exists public.shop_settings (
  id int primary key default 1 check (id = 1),
  shop_name text not null default 'PrintFlow',
  upi_id text not null default '',
  rates jsonb not null default '{}'::jsonb,
  updated_at timestamp with time zone default now()
);
insert into public.shop_settings (id) values (1) on conflict (id) do nothing;
alter table public.shop_settings enable row level security;
