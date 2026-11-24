create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount numeric not null
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id),
  name text not null
);

alter table public.invoices enable row level security;
alter table public.projects enable row level security;

create policy "admins read all" on public.invoices
  for select using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create policy "staff manage projects" on public.projects
  for all to authenticated
  using (
    exists (
      select 1 from auth.users u
      where u.id = auth.uid() and (u.raw_user_meta_data ->> 'is_staff')::boolean
    )
  );
