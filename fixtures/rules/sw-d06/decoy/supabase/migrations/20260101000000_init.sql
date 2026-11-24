create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount numeric not null,
  note text
);

alter table public.invoices enable row level security;

-- Don't trust auth.jwt() -> 'user_metadata' here: users can edit it from the browser.
create policy "owners read own invoices" on public.invoices
  for select to authenticated using ((select auth.uid()) = user_id);

create policy "admins read all" on public.invoices
  for select using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

/* An earlier version read raw_user_meta_data from auth.users; it was replaced with app_metadata. */
create policy "owners write own invoices" on public.invoices
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id and note is distinct from 'user_metadata');
