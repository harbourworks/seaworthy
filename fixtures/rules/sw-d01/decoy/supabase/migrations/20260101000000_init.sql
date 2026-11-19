create table public.invoices (id uuid primary key, user_id uuid references auth.users (id));
create table public."TeamMembers" (id uuid primary key, user_id uuid references auth.users (id));
create table public.audit_log (id bigint primary key, detail text);

DO $body$
DECLARE
  t TEXT;
BEGIN
  <<tables>>
  FOREACH t IN ARRAY ARRAY['invoices', 'TeamMembers']::text[]
  LOOP
    EXECUTE format('ALTER TABLE ONLY public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP tables;
END
$body$;

do $$
declare
  name text;
begin
  foreach name in array array['audit_log'] loop
    execute format('alter table %s enable row level security; revoke all on table %1$s from anon, authenticated', name);
  end loop;
end $$;
