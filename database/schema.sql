-- PrintFlow database setup (fresh install).
-- Already have the old tables? Run database/migrations/002_secure_backend_only.sql instead.
--
-- Security model: the browser NEVER talks to these tables. Only the FastAPI backend
-- does, using the service key (which bypasses RLS). RLS is enabled with no policies,
-- so the public/anon key cannot read or write anything.

create table if not exists public.orders (
  id text primary key,
  customer_name text not null,
  phone text not null,
  file_name text not null,
  file_key text not null,
  files jsonb not null default '[]'::jsonb,
  file_size_mb numeric default 1.0,
  file_status text default 'IN CLOUD',
  total_doc_pages int not null,
  page_range_mode text default 'all',
  page_range_spec text default 'All',
  effective_pages int not null,
  orientation text default 'portrait',
  n_up_layout int default 1,
  copies int not null,
  color_mode text not null,
  sides text not null,
  paper_size text not null,
  paper_gsm text not null,
  binding text not null,
  address text not null,
  landmark text,
  pincode text not null,
  instructions text,
  total_amount numeric not null,
  utr_number text not null default '',
  razorpay_order_id text,
  paid_at timestamp with time zone,
  order_status text default 'Awaiting Payment',
  rejection_reason text,
  created_at timestamp with time zone default now()
);

create index if not exists orders_created_at_idx on public.orders (created_at desc);
create index if not exists orders_utr_idx on public.orders (utr_number) where utr_number <> '';

create table if not exists public.shop_settings (
  id int primary key default 1 check (id = 1),
  shop_name text not null default 'PrintFlow',
  upi_id text not null default '',
  rates jsonb not null default '{}'::jsonb,
  updated_at timestamp with time zone default now()
);
insert into public.shop_settings (id) values (1) on conflict (id) do nothing;

alter table public.orders enable row level security;
alter table public.shop_settings enable row level security;
-- Intentionally no policies: anon/authenticated roles get no access.
