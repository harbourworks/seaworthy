create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  total numeric not null
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);

do $$
declare
  tbl text;
begin
  foreach tbl in array array['orders', 'notes']
  loop
    execute format(
      'create policy "owner reads %1$s" on public.%1$I for select to authenticated using ((select auth.uid()) = user_id)',
      tbl
    );
  end loop;
end
$$;
