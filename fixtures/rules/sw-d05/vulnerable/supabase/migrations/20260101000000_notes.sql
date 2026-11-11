create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);
alter table public.notes enable row level security;
create policy "Users read own notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);

create view public.note_previews as
  select n.id, n.user_id, left(n.body, 80) as preview
  from public.notes n;

create or replace function public.note_count(uid uuid)
returns bigint
language sql
security definer
as $$
  select count(*) from notes where user_id = uid;
$$;
