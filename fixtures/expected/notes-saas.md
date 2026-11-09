# notes-saas: answer key

Next.js 14 App Router, Supabase, Stripe, Postgres via `pg`. Paths are relative to `fixtures/apps/notes-saas/`.

## Planted flaws

| Rule | File | Line | What is wrong |
| --- | --- | --- | --- |
| SW-S01 | `lib/stripe.ts` | 3 | Stripe live secret key hard-coded |
| SW-S01 | `.env` | 4, 5, 6 | Service-role key, database password and webhook secret committed |
| SW-S02 | `.env` | 1 | `.env` committed |
| SW-S02 | `.gitignore` | 1 | `.env` not listed |
| SW-S03 | `.env` | 3 | Service-role key given a `NEXT_PUBLIC_` prefix, so it is bundled for the browser |
| SW-S03 | `lib/supabase-browser.ts` | 6 | Browser Supabase client built with the service-role key; imported by the client page `app/notes/page.tsx` line 4 |
| SW-D01 | `supabase/migrations/0001_init.sql` | 20 | `payments` table created with no `enable row level security` |
| SW-D02 | `supabase/migrations/0001_init.sql` | 18 | `notes` policy `using (true)`: every user reads every note |
| SW-A01 | `app/api/notes/[id]/route.ts` | 21 | `DELETE` handler has no auth check at all |
| SW-A02 | `app/api/notes/[id]/route.ts` | 14 | `GET` checks login but fetches by client-supplied ID with no `user_id` filter, via the admin client that bypasses RLS |
| SW-A05 | `app/api/search/route.ts` | 13 | Query string `q` concatenated into SQL |
| SW-P01 | `app/api/webhooks/stripe/route.ts` | 5 | Body parsed with `JSON.parse`, no `stripe.webhooks.constructEvent`; anyone can POST a fake "paid" event |
| SW-P02 | `app/api/checkout/route.ts` | 11, 20 | `amount` taken from the request body and used as `unit_amount` |
| SW-X01 | `package.json` | 12 | `next` 14.1.0 is old; expected to have known advisories. **Confirm the exact advisories against OSV during the teardown, don't assume them.** |
| SW-B01 | `next.config.js` | 2 | No `headers()`: no CSP, frame options or HSTS |

## Decoys (should NOT be flagged)

| Where | Why it is fine |
| --- | --- |
| `app/api/search/route.ts` line 13, the `user.id` part | Comes from the verified session, not the request. Only `q` is user input. Flagging the whole line still counts as a catch for SW-A05, but note whether a tool can tell the difference |
| `supabase/migrations/0001_init.sql`, `profiles` table | RLS on, policy scoped to `auth.uid() = id` |
| `lib/supabase-server.ts` | Service-role key used server-side only, without a public prefix |
| `.env` line 2 | Supabase anon key is meant to be public |
