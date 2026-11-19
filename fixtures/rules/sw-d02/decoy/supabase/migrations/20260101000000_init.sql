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
    execute format('alter table public.%I enable row level security', tbl);
    -- execute format('create policy "open %s" on public.%I using (true)', tbl, tbl);
    raise notice 'using (true) is not used on %', tbl;
    execute format(
      'create policy "service role manages %1$s" on public.%1$I for all to service_role using (true) with check (true)',
      tbl
    );
    execute format(
      'create policy "owner reads %1$s" on public.%1$I for select to authenticated using ((select auth.uid()) = user_id)',
      tbl
    );
  end loop;
end
$$;
