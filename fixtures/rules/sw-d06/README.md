# SW-D06 fixtures

Row-level security policies on `public.invoices` and `public.projects` that decide who is an admin or staff member.

- `vulnerable/`: the issue's `invoices` policy, which reads the role from `auth.jwt() -> 'user_metadata'`, and a
  `projects` policy that reads `raw_user_meta_data` from `auth.users` in a subquery. Both are flagged, at the
  `create policy` line.
- `fixed/`: the same policies reading the role from `auth.jwt() -> 'app_metadata'` and from a `user_roles` table
  joined on `auth.uid()`. Nothing is flagged.
- `decoy/`: an owner policy (`auth.uid() = user_id`), an admin policy that reads only `app_metadata`, comments that
  mention `user_metadata` and `raw_user_meta_data`, and a `'user_metadata'` string compared with a column rather
  than used as a JWT path. Nothing is flagged.
