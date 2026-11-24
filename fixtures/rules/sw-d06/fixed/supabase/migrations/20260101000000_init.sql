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

create table public.user_roles (
  user_id uuid primary key references auth.users (id),
  role text not null
);

alter table public.invoices enable row level security;
alter table public.projects enable row level security;
alter table public.user_roles enable row level security;

-- The role is set only from server code with the service role, so users can't change it.
create policy "admins read all" on public.invoices
  for select using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

create policy "staff manage projects" on public.projects
  for all to authenticated
  using (
    exists (
      select 1 from public.user_roles r
      where r.user_id = (select auth.uid()) and r.role = 'staff'
    )
  );
