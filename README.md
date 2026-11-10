# Seaworthy

**A pre-launch security check for AI-built apps.** Runs on your machine. Your code never leaves it.

Cursor, Claude Code, Lovable and Bolt write working code fast. They also skip auth checks, leak keys into the browser and leave database tables open to anyone with your public key. Seaworthy finds those gaps before your users do, and tells you how to fix each one in plain English.

```
npx seaworthy-cli
```

No account, no install, no upload. Node 20 or later.

```
  Seaworthy 0.1.0  ·  notes-app  ·  Next.js, React, Supabase, Stripe
  42 files, 12 rules, 180 ms. Your code never left this machine.

  ✖ Not seaworthy: 3 critical, 2 high

   CRITICAL   Table public.payments has no row-level security   SW-D01
  supabase/migrations/0001_init.sql:20
  > 20 │ create table public.payments (
  Why  Anyone with your public anon key, which is in your frontend bundle,
       can read, edit and delete every row.
  Fix  Add a migration with `alter table public.payments enable row level
       security;`, then add policies for the access you actually want.
```

## What it checks

| Area | Checks |
| --- | --- |
| **Secrets** | Keys committed to the repo (with Supabase anon vs service-role told apart) · `.env` files committed or not git-ignored · secrets given a public prefix (`NEXT_PUBLIC_`, `VITE_` …) · LLM keys in browser code |
| **Database and storage** | Supabase tables without row-level security · policies that let everyone in · open Firestore, Realtime Database and Storage rules, including forgotten test mode |
| **API routes** | No auth check · records fetched by ID without an ownership check · no rate limit on costly endpoints · CORS that lets any site make credentialed requests · SQL built from user input |
| **Payments** | Stripe webhooks that don't verify the signature · prices or amounts taken from the client |
| **AI and agents** | User input in the system prompt · model output rendered as HTML or run as code · agent tools with shell or file access and no guard · MCP configs with plain-text secrets or open servers |
| **Dependencies** | Known vulnerabilities, from [OSV](https://osv.dev) |
| **Headers** | Missing Content-Security-Policy, frame protection and HSTS |

Checks run only when they apply to your stack: Next.js, React, Vue, Svelte, Supabase, Firebase, Stripe and the main LLM SDKs. They read what your code does, not just words in it, and are tuned for few false alarms. `seaworthy rules` lists them all and `seaworthy explain SW-D01` explains one.

## In CI (GitHub Actions)

```
npx seaworthy-cli init
```

This adds `seaworthy.config.json` and `.github/workflows/seaworthy.yml`. Commit both, and every pull request and push to `main` is scanned: findings appear in the repo's Security tab and as annotations on pull requests (SARIF, via GitHub code scanning), and the check fails on high or critical findings. Code scanning is free on public repos; private repos need it enabled.

**Pull-request checks (Pro):** `npx seaworthy-cli init --pr` writes a workflow that scans each pull request against its base branch and posts one comment, updated on every push, with only the problems the pull request introduces in full, the ones it fixes listed, and the ones already there counted. The check fails only on new findings at or above your threshold. Add your licence key as a repository secret called `SEAWORTHY_LICENCE`; without one, pull requests get a full scan. The same comparison runs locally with `seaworthy --baseline origin/main`.

## Usage

```
npx seaworthy-cli                        # scan the current folder
npx seaworthy-cli path/to/app            # scan another folder
npx seaworthy-cli --format json          # machine-readable output
npx seaworthy-cli --format sarif         # SARIF for GitHub code scanning (seaworthy.sarif)
npx seaworthy-cli --format markdown      # Markdown for CI summaries and comments (seaworthy-report.md)
npx seaworthy-cli --fail-on critical     # only fail on critical findings
npx seaworthy-cli --offline              # make no network calls at all
```

Exit codes: `0` nothing at or above your threshold, `1` findings at or above it (so CI fails), `2` the tool itself hit an error.

Silence one finding with a comment on the line, or the line above, giving a reason: `// seaworthy-ignore SW-S03 public demo key, rotated weekly`. A comment with no reason doesn't count.

Configure a project with `seaworthy.config.json`:

```json
{ "failOn": "high", "minConfidence": "high", "ignore": ["fixtures/**"], "rules": { "SW-B01": "off" } }
```

## Privacy

Seaworthy reads your files locally and never sends code, findings or file names anywhere. Two things use the network, and both are optional:

- **The dependency check** sends package names and versions (nothing else) to [osv.dev](https://osv.dev). `--offline` skips it.
- **A paid licence** is checked against the licence server at most once a day, sending the key and a machine name. The free version never does this.

## Plans

Every check is free. **Pro** (£12 a month or £99 a year) adds pull-request checks that show only new problems, a self-contained HTML report, scan history and before/after comparison. **Agency** (£349 a year) adds white-label reports and scanning every project in a folder. Paid features never block a scan. See [dynamomaritime.com/seaworthy](https://dynamomaritime.com/seaworthy).

Buying and using a plan takes three steps:

```
npx seaworthy-cli buy              # see the plans and open the checkout
                                   # then get your key: https://polar.sh/dynamo-maritime/portal
npx seaworthy-cli login <key>      # turn it on for this machine
```

In the portal, enter the email you bought with and Polar sends a verification code; your key is under your plan. In CI, add the key as a repository secret called `SEAWORTHY_LICENCE` instead of logging in.

## It's an aid, not a guarantee

Seaworthy catches common, serious mistakes. It is not a security audit or certification, and no tool finds everything.

## Licence and support

Source-available, not open source: the scanner is under the [Functional Source License](LICENSE) (FSL-1.1-ALv2), free for any use except a competing product, and each release becomes Apache 2.0 two years after it ships. The paid features are under the [Seaworthy Commercial Licence](LICENSE-COMMERCIAL.md).

Help, false alarms and security reports: [support@dynamomaritime.com](mailto:support@dynamomaritime.com) · [dynamomaritime.com/support](https://dynamomaritime.com/support)

Seaworthy is a trading name of Dynamo Maritime Ltd, registered in England and Wales, company number 17152743.
