create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null,
  updated_at timestamptz
);
alter table public.notes enable row level security;
create policy "Users read own notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);

-- A view over a table with no RLS (that table is SW-D01's finding, not SW-D05's).
create table public.tags (id int primary key, label text);
create view public.tag_labels as select label from public.tags;

-- A view fixed by a later migration's alter view.
create view public.note_ids as select id, user_id from public.notes;

-- A trigger function.
create function public.touch_note() returns trigger
language plpgsql security definer as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- A definer function nobody can call through the API.
create function public.purge_notes() returns void
language sql security definer as $$ delete from notes; $$;
revoke execute on function public.purge_notes() from public, anon, authenticated;

-- A view that is dropped later.
create view public.old_notes as select * from public.notes;
drop view if exists public.old_notes;

-- A view that is public by design.
-- seaworthy-ignore SW-D05 shows only note counts, no note content
create view public.note_totals as select count(*) as total from public.notes;
