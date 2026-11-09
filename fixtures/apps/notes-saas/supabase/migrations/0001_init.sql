create table public.profiles (
  id uuid primary key references auth.users (id),
  plan text not null default 'free'
);
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles
  for select using (auth.uid() = id);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "Notes are readable" on public.notes
  for select using (true);

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount integer not null,
  created_at timestamptz not null default now()
);
