# SW-A02 fixtures

Server actions and a route handler that change teammates' rows through the Supabase service-role client,
which skips row-level security.

- `vulnerable/`: handlers that only check someone is signed in (`requireUser`) before changing a row by an ID
  from the request. Four of them look at the role but don't stop the query: the result is stored and never
  used, the `if` only logs, `requireRole` runs after the delete, or `requireRole` isn't awaited. All six are flagged.
- `fixed/`: the same handlers with an owner filter (`.eq("user_id", user.id)`) or with the role check moved
  before the query so that it throws or returns. Nothing is flagged.
- `decoy/`: the false positives from issue #37. IDs that come back from `auth.admin.createUser`,
  `auth.admin.inviteUserByEmail` or `.insert(...).select()`, and admin-only handlers guarded by
  `requireRole`, `requireAdmin`, `assertPermission`, `if (!isAdmin(...)) throw`, `if (!hasRole(...))
  redirect(...)` and `role !== "owner"` comparisons. Nothing is flagged.

No real keys: every secret is read from an environment variable.
