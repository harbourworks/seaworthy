create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  total numeric not null
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  body text not null
);

do $$
declare
  tbl text;
begin
  foreach tbl in array array['orders', 'notes']
  loop
    execute format('alter table public.%I enable row level security', tbl);
    execute format(
      'create policy "signed in write %1$s" on public.%1$I for all to authenticated using (true) with check (true)',
      tbl
    );
  end loop;
end
$$;
