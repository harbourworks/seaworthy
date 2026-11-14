# Seaworthy

[![npm](https://img.shields.io/npm/v/seaworthy-cli)](https://www.npmjs.com/package/seaworthy-cli) [![CI](https://github.com/harbourworks/seaworthy/actions/workflows/seaworthy.yml/badge.svg)](https://github.com/harbourworks/seaworthy/actions/workflows/seaworthy.yml) [![Licence: FSL-1.1-ALv2](https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue)](LICENSE)

**A pre-launch security check for AI-built apps: run it before you deploy, add payments or make a repo public.** Runs on your machine. Your code never leaves it.

Cursor, Claude Code, Lovable and Bolt write working code fast. They also skip auth checks, leak keys into the browser and leave database tables open to anyone with your public key. Seaworthy finds those gaps before your users do, and tells you how to fix each one in plain English.

```
npx seaworthy-cli
```

No account, no install, no upload. Node 20 or later.

```
  Seaworthy 0.7.0  ·  notes-app  ·  Next.js, React, Supabase, Stripe
  42 files, 22 rules, 180 ms. Your code never left this machine.

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
| **Secrets** | Keys committed to the repo, now or in its git history (with Supabase anon vs service-role told apart) · `.env` files committed or not git-ignored · secrets given a public prefix (`NEXT_PUBLIC_`, `VITE_` …) · LLM keys in browser code |
| **Database and storage** | Supabase tables without row-level security · policies that let everyone in · views and `security definer` functions that bypass row-level security · public Supabase buckets holding private files · open Firestore, Realtime Database and Storage rules, including forgotten test mode |
| **API routes** | No auth check · records fetched by ID without an ownership check · no rate limit on costly endpoints · CORS that lets any site make credentialed requests · SQL built from user input |
| **Payments** | Stripe webhooks that don't verify the signature · prices or amounts taken from the client |
| **AI and agents** | User input in the system prompt · model output rendered as HTML or run as code · agent tools with shell or file access and no guard · MCP configs with plain-text secrets or open servers · MCP servers auto-approved in Claude Code settings or launched through a shell |
| **Dependencies** | Known vulnerabilities, from [OSV](https://osv.dev) · packages that don't exist on npm (often invented by AI tools) or are brand new |
| **Headers** | Missing Content-Security-Policy, frame protection and HSTS |

The code checks read JavaScript and TypeScript, including JSX, Vue, Svelte and Astro. Stack-specific checks run only when that stack is detected (Next.js, Supabase, Firebase, Stripe, MCP). They read what your code does, not just words in it, and are tuned for few false alarms. **[Every rule, and where each one stops](docs/rules.md)**; `seaworthy explain SW-D01` explains one.

## When to run it

- Before the first deploy.
- After adding login, payments, file uploads or an AI feature.
- Before making a repo public.
- On every pull request, in CI (below).

## Use it with your AI assistant

- **MCP server:** `claude mcp add seaworthy -- npx -y seaworthy-cli mcp` in Claude Code. For Cursor (`.cursor/mcp.json`) or Claude Desktop, add `{ "mcpServers": { "seaworthy": { "command": "npx", "args": ["-y", "seaworthy-cli", "mcp"] } } }`. Your assistant gets `scan_project`, `explain_finding` and `list_rules`, running locally. Findings come back without code excerpts, so secrets aren't copied into the chat.
- **Rules file:** `npx seaworthy-cli init --agent` adds a short "run the check before deploying" step to your AGENTS.md, CLAUDE.md, Cursor rules or Copilot instructions. It shows the text and asks first. The snippets are also in [agent-rules/](agent-rules).
- **Any assistant:** `npx seaworthy-cli --format json` gives a [stable JSON shape](docs/cli.md#json-output) with a fix and, where useful, a paste-ready prompt for each finding.

## In CI (GitHub Actions)

```
npx seaworthy-cli init
```

This adds `seaworthy.config.json` and `.github/workflows/seaworthy.yml`. Commit both, and every pull request and push to `main` is scanned: findings appear in the repo's Security tab and as annotations on pull requests (SARIF, via GitHub code scanning), and the check fails on high or critical findings. Code scanning is free on public repos; private repos need it enabled.

**Pull-request checks (Pro):** `npx seaworthy-cli init --pr` writes a workflow that scans each pull request against its base branch and posts one comment, updated on every push, with only the problems the pull request introduces in full, the ones it fixes listed, and the ones already there counted. The check fails only on new findings at or above your threshold. Add your licence key as a repository secret called `SEAWORTHY_LICENCE`; without one, pull requests get a full scan. The same comparison runs locally with `seaworthy --baseline origin/main`.

**Scheduled scans (Pro):** `npx seaworthy-cli init --schedule` adds a weekly scan that alerts Slack, any webhook or your email when new problems appear, including new advisories for dependencies you haven't touched. Alerts never include code or secrets. [Set-up](docs/cli.md#scheduled-scans-and-alerts-pro).

## Usage

```
npx seaworthy-cli                        # scan the current folder
npx seaworthy-cli path/to/app            # scan another folder
npx seaworthy-cli --format json          # machine-readable output
npx seaworthy-cli --format sarif         # SARIF for GitHub code scanning (seaworthy.sarif)
npx seaworthy-cli --format markdown      # Markdown for CI summaries and comments (seaworthy-report.md)
npx seaworthy-cli mcp                    # run as an MCP server for AI assistants (stdio)
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

Seaworthy reads your files locally and never sends code, findings or file names anywhere. Three things use the network, and all are optional:

- **The vulnerability check** (SW-X01) sends package names and versions (nothing else) to [osv.dev](https://osv.dev).
- **The package-name check** (SW-X02) sends package names only (no versions) to the public npm registry, registry.npmjs.org, as `npm install` would. It skips your project's own workspace packages, packages from a private registry set in a `.npmrc` in the project (`registry=` for all packages, or `@scope:registry=` for one scope), and dependencies whose version starts with `file:`, `link:`, `workspace:`, `portal:`, `git:`, `git+…:` (such as `git+ssh:`), `github:`, `gitlab:`, `bitbucket:`, `http:` or `https:`. Your user-level or global `.npmrc` isn't read, and any other dependency, such as a bare path (`../lib`) or GitHub shorthand (`user/repo`), is looked up by name.
- **A paid licence** is checked against the licence server at most once a day, sending the key and a machine name. The free version never does this.

`--offline` skips both dependency lookups.

## Plans

Every check is free. **Pro** (£12 a month or £99 a year) adds pull-request checks that show only new problems, scheduled scans with Slack and email alerts, a self-contained HTML report, scan history and before/after comparison. **Agency** (£349 a year) adds white-label reports and scanning every project in a folder. Paid features never block a scan. See [dynamomaritime.com/seaworthy](https://dynamomaritime.com/seaworthy).

Buying and using a plan takes three steps:

```
npx seaworthy-cli buy              # see the plans and open the checkout
                                   # then get your key: https://polar.sh/dynamo-maritime/portal
npx seaworthy-cli login <key>      # turn it on for this machine
```

In the portal, enter the email you bought with and Polar sends a verification code; your key is under your plan. In CI, add the key as a repository secret called `SEAWORTHY_LICENCE` instead of logging in.

## It's an aid, not a guarantee

Seaworthy catches common, serious mistakes. It is not a security audit or certification, and no tool finds everything.

## Licence, security and support

Full reference: [docs/cli.md](docs/cli.md) (commands, options, exit codes, JSON output). Changes: [CHANGELOG.md](CHANGELOG.md). Found a security problem in Seaworthy itself? See [SECURITY.md](SECURITY.md).

Source-available, not open source: the scanner is under the [Functional Source License](LICENSE) (FSL-1.1-ALv2), free for any use except a competing product, and each release becomes Apache 2.0 two years after it ships. The paid features are under the [Seaworthy Commercial Licence](LICENSE-COMMERCIAL.md).

Help, false alarms and security reports: [support@dynamomaritime.com](mailto:support@dynamomaritime.com) · [dynamomaritime.com/support](https://dynamomaritime.com/support)

Seaworthy is a trading name of Dynamo Maritime Ltd, registered in England and Wales, company number 17152743.
