# SW-A06 fixtures

Next.js server code that decides who is signed in with Supabase's `auth.getSession()`, which reads the
session from the request's cookies without verifying it.

- `vulnerable/`: the `invoices` route handler from issue #19 (`if (!session)` returns 401, and
  `session.user.id` is the owner in the query), middleware that redirects to `/login` when
  `data.session` is missing, a server component page that calls `redirect("/login")`, and a server
  action that inserts a note with `session?.user.id` as its owner. All four are flagged, at the
  `getSession()` call.
- `fixed/`: the same files with `auth.getUser()` or `auth.getClaims()` instead. Nothing is flagged.
- `decoy/`: `getSession()` in a `"use client"` component to show the email address, a route handler
  that calls `getUser()` first and then `getSession()` only for the `access_token`, and a page that
  calls an imported `requireUser()` helper (which calls `getUser()`) before reading the session.
  Nothing is flagged.

No real keys: every key is read from an environment variable.
