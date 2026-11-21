# SW-A03 fixtures

Rate limiters whose names contain "rate limit" inside a longer identifier or path.

- `vulnerable/`: an invite route that sends email and a summarise route that calls OpenAI, with no
  limiter anywhere. The summarise route uses names that only look similar (`unlimitedPlan`,
  `accurateLimit` in `src/lib/plans.ts`). Both routes are reported.
- `fixed/`: the issue's reproduction. `src/middleware.ts` limits every `/api/` request per IP with an
  `isRateLimited(...)` helper imported from `@/lib/rate-limit`, so the invite route isn't reported.
- `decoy/`: the summarise route calls `checkRateLimit(...)` itself, and the invite route calls a
  `guard()` helper whose module uses `checkRateLimit` and an `apiRateLimit` setting. Nothing is
  reported.

SW-A01 and SW-B01 also report on these projects: they have no auth checks and no security headers.
No real keys: every secret is read from an environment variable.
