# Changelog

All notable changes to seaworthy-cli. Versions follow [semantic versioning](https://semver.org); while it's 0.x, a minor version can change behaviour.

## 0.7.3 (24 November 2026)

Fewer false alarms from SW-D01, SW-P01, SW-S01 and SW-A02, and SW-D02 now checks policies created in loops.

- **SW-D01 and SW-D02 with DO blocks:** in Supabase migrations, a `do $$ … $$` block that loops over a written-out list of tables (`foreach t in array array['orders', 'notes'] loop`) and runs `execute format(…, t)` is now read table by table. Tables it enables row-level security on are no longer reported by SW-D01, and the policies it creates are checked by SW-D02, reported at the `execute` line, one finding per table. When a block that mentions row level security uses other dynamic SQL Seaworthy can't follow, its tables are reported by SW-D01 as "may not have row-level security" at low confidence (shown with `--min-confidence low`) instead of high.
- **Findings at the same spot:** two findings from one rule at the same file, line and column are now both shown when their titles differ. Before, only the first was kept.
- **SW-P01 and split webhook handlers:** a file that handles Stripe events but doesn't read the request body is no longer reported when a file that imports it verifies the signature (one level of importers, including `@/` and `~/` imports). When it is still reported, it is at medium confidence, so it's hidden by default (shown with `--min-confidence medium`), and the message no longer says the file reads the request body. A file named like a webhook no longer raises the confidence. Webhooks that read the body themselves are reported as before.
- **SW-S01 and example database URLs:** connection strings at reserved example hosts (`example.com`, `example.org`, `example.net` and their subdomains, and hosts ending in `.example`, `.test`, `.invalid` or `.localhost`) are no longer reported, nor are ones whose password is exactly `password`, `pass`, `secret`, `postgres`, `root`, `admin` or `changeme` (any case), whatever the host.
- **SW-A02 and admin actions:** IDs that come from an awaited `auth.admin.createUser`, `auth.admin.inviteUserByEmail` or `.insert(…).select()` are no longer treated as request input. A query is no longer reported when the handler first runs an awaited role guard (`requireRole`, `requireAdmin`, `requirePermission` or their plurals, `assertRole`, `assertAdmin`, `assertPermission`, `ensureAdmin`), or an `if` on `!isAdmin(…)`, `!hasRole(…)`, `!can(…)` or `role !== "admin"`/`"owner"`/`"manager"` that throws, returns, or calls a Next.js exit such as `redirect` or `notFound`.
- **SW-X02 and a linked `.npmrc`:** a project `.npmrc` that is a symlink to a file is now read for its registry settings, so packages from your private registry are no longer looked up on npm. A broken link or a link to a folder is skipped.

## 0.7.2 (20 November 2026)

Fewer false alarms from SW-S04 and SW-X02, and fewer package names sent to npm.

- **SW-S04 and `dangerouslyAllowBrowser: false`:** in Vue and Svelte files, and in other files that are text-matched, `dangerouslyAllowBrowser: false` is no longer reported when there's a space or a line break before `false`. `true` and other values are still reported.
- **Files with decorators:** JavaScript and TypeScript files that use decorators (`@Component`, `@Input()`, `constructor(@Inject(X) x)`, `@observable accessor busy`, `export @dec class`) are now read as code instead of being text-matched. SW-S04 no longer flags `dangerouslyAllowBrowser` in type declarations in these files, and the API route, Stripe checkout price, SQL, prompt and agent-tool checks now cover them, so a problem in such a file that was missed before can now be reported.
- **SW-X02 and local or GitHub dependencies:** dependencies installed from a folder (`../lib`, `./lib`, `/opt/lib`, `~/lib`, `.`, `..`) or written as GitHub shorthand (`owner/repo`, `owner/repo#ref`) are no longer looked up on the npm registry or reported as "isn't on npm".
- **SW-X02 and a gitignored `.npmrc`:** the registry settings (`registry=` and `@scope:registry=`) in a `.npmrc` that `.gitignore` hides are now used when it sits in the scanned folder or next to a `package.json`, so packages from your private registry are no longer looked up on npm. The file is only read for those settings: other checks don't scan it, and the `ignore` list in `seaworthy.config.json` still excludes it.

## 0.7.1 (14 November 2026)

- **Class `accessor` fields:** JavaScript and TypeScript files with fields like `accessor count = 0` are now read as code instead of being skipped or text-matched. SW-S04 no longer flags `dangerouslyAllowBrowser` in type declarations or set to `false` in these files, and the API route, Stripe checkout price, SQL, prompt and agent-tool checks now cover them, so a problem in such a file that was missed before can now be reported. Fields with a decorator (`@observable accessor busy = false`) are still text-matched.

## 0.7.0 (13 November 2026)

Two new checks, for Supabase and for MCP servers in Claude Code projects.

- **SW-D05:** Supabase views that bypass row-level security. A view in the public schema without `security_invoker = true` that reads a table with RLS on is reported as high, because anyone with your anon key can read every row through it. `security definer` functions with no `set search_path` that the API roles can still call are reported too, at medium confidence (shown with `--min-confidence medium`).
- **SW-L05:** MCP servers that start without asking or run through a shell. `"enableAllProjectMcpServers": true` in `.claude/settings.json` or `.claude/settings.local.json` is reported as medium, even before the repo has an `.mcp.json`. MCP servers that pipe a download into a shell (`curl ... | sh`, `irm ... | iex`) are reported as low. Other servers started with `bash -c`, `cmd /c` or `powershell -Command` are reported as low at medium confidence; `cmd /c` that only starts one program, the usual way to run npx on Windows, isn't. Seaworthy now reads Claude Code project settings files for this.

## 0.6.0 (10 November 2026)

Every check in the v1 plan is now built.

- **SW-X02:** dependencies that don't exist on the npm registry (names AI tools invent, which anyone can register) or were first published in the last 30 days. Only names are sent, as `npm install` would; `--offline` skips it.
- **SW-D04, Supabase half:** public storage buckets that look like they hold private files, from migrations, `seed.sql`, `supabase/config.toml` or `createBucket` calls.
- **SW-S01 in git history:** when you scan a repository's top folder, secrets in earlier versions of files are reported with the commit that added them. In pull-request checks, only leaks added by the pull request count as new.

- **Scheduled scans with alerts (Pro):** `seaworthy scan --notify` alerts Slack, any https webhook, or email through your own SMTP server when new problems appear; `--notify-on failing|always` widens it. `seaworthy init --schedule` writes a weekly workflow that keeps scan history in the Actions cache. Alerts never include code or secrets.
- Workflows and the Action use the latest action versions (checkout v7, setup-node v7, github-script v9).

## 0.5.0 (10 November 2026)

- **`seaworthy mcp`:** an MCP server over stdio for AI coding assistants, with `scan_project`, `explain_finding` and `list_rules`. Local and read-only; findings come back without code excerpts.
- **`seaworthy init --agent`:** adds a short "run the check before deploying" step to AGENTS.md, CLAUDE.md, Cursor rules or Copilot instructions. It shows the text and asks first.
- **GitHub Action:** `uses: harbourworks/seaworthy@<version>` runs the scan, uploads SARIF and fails on the threshold.
- **Docs:** every rule with what it reads and where it stops ([docs/rules.md](docs/rules.md)), and a full CLI reference ([docs/cli.md](docs/cli.md)).
- Workflows use `github/codeql-action/upload-sarif@v4`.
- The package now includes `dist/THIRD-PARTY-NOTICES.txt` for the bundled MCP SDK, and `server.json` and `mcpName` for the MCP Registry.
- SW-P02's explanation no longer says a plan can be bought "for 1p" (Stripe has a higher minimum).

## 0.4.0 (10 November 2026)

- **`seaworthy buy`** (alias `upgrade`): the plans, the checkout opened in your browser, and what to do after paying.
- **`seaworthy login`** with no key says where your key is and opens the customer portal. Every key message links to the portal.

## 0.3.0 (10 November 2026)

- **Pull-request checks (Pro):** `--baseline <ref>` reports only the findings a change introduces. `seaworthy init --pr` writes a workflow that keeps one pull-request comment up to date.
- **`--format markdown`** for CI summaries and comments.

## 0.2.1 (10 November 2026)

- HTML report polish; the CI workflow uses Node 22 and always reports the outcome.

## 0.2.0 (10 November 2026)

- **`seaworthy init`:** a config file and a GitHub Actions workflow.
- **`--format sarif`** for GitHub code scanning.
- Fewer false alarms from a pass over 18 real projects, and a masking fix for database passwords containing `@`.

## 0.1.1 (10 November 2026)

- Tagged but not published; its fixes shipped in 0.2.0.

## 0.1.0 (10 November 2026)

- First release: 21 checks across secrets, Supabase, Firebase, API routes, payments, LLM and MCP risks, dependencies and headers; terminal and JSON output; Pro and Agency plans.
