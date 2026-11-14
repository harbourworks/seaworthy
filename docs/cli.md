# Seaworthy CLI reference

Seaworthy is a pre-launch security check for apps built with AI coding tools. It runs on your machine: your code is never uploaded.

```
npx seaworthy-cli                  # scan the current folder
```

Node 20 or later. No install needed; `npm i -D seaworthy-cli` pins a version if you prefer.

## When to run it

- Before the first deploy.
- After adding login, payments, file uploads or an AI feature.
- Before making a repo public.
- In CI, on every pull request and push (`seaworthy init`).

## Commands

| Command | What it does |
| --- | --- |
| `seaworthy [scan] [path]` | Scan a project (default: the current folder) |
| `seaworthy explain <rule-id>` | Explain one rule, with an example of the problem and the fix |
| `seaworthy rules` | List every rule |
| `seaworthy init [path]` | Add `seaworthy.config.json` and a GitHub Actions workflow; `--pr` for pull-request comments, `--schedule` for a weekly scan with alerts (both Pro), `--agent` for an AI assistant's rules file |
| `seaworthy mcp` | Run as an MCP server over stdio, for AI coding assistants (see below) |
| `seaworthy buy` | See the plans and open the checkout |
| `seaworthy login <key>` / `logout` / `status` | Manage a Pro or Agency licence on this machine |
| `seaworthy history` / `compare` | Scan history and before/after comparison (Pro) |

## Options

| Option | Meaning |
| --- | --- |
| `--format terminal\|json\|sarif\|markdown\|html` | Output format. Default `terminal`. `json` goes to stdout; `sarif`, `markdown` and `html` are written to a file. `html` is Pro. |
| `--output <file>` | Where to write SARIF, Markdown or HTML (defaults: `seaworthy.sarif`, `seaworthy-report.md`, `seaworthy-report.html`) |
| `--fail-on critical\|high\|medium\|low` | Exit 1 when a finding is at or above this severity. Default `high`. |
| `--min-confidence high\|medium\|low` | Hide findings below this confidence. Default `high`. |
| `--config <file>` | Config file. Default `./seaworthy.config.json`. |
| `--offline` | Make no network calls at all (skips both dependency lookups: OSV and the npm registry) |
| `--baseline <ref>` | Report only findings that are new since a git ref, such as `origin/main` (Pro) |
| `--all` | Scan every project in a folder, one combined report (Agency) |
| `--notify` | Send an alert to Slack, a webhook or email (Pro; see below) |
| `--notify-on new\|failing\|always` | When to alert. Default `new`: only when problems at or above `--fail-on` appear that weren't in the last scan |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | At least one finding at or above the threshold (with `--baseline`: at least one new one) |
| `2` | Seaworthy itself hit an error (bad option, unreadable config, not a folder), or an alert couldn't be delivered |

## JSON output

`npx seaworthy-cli --format json` prints one JSON object to stdout. Notes and messages go to stderr, so stdout always parses. The shape is stable within a major version.

```json
{
  "tool": "seaworthy",
  "version": "0.7.0",
  "failed": true,
  "stack": ["nextjs", "react", "supabase", "stripe"],
  "filesScanned": 16,
  "rulesRun": ["SW-S01", "SW-D01"],
  "findings": [
    {
      "ruleId": "SW-D01",
      "title": "Table public.payments has no row-level security",
      "severity": "critical",
      "confidence": "high",
      "file": "supabase/migrations/0001_init.sql",
      "line": 20,
      "column": 1,
      "why": "public.payments is created without row-level security...",
      "fix": "Add a migration with `alter table public.payments enable row level security;`...",
      "fixPrompt": "In supabase/migrations, ..."
    }
  ],
  "hiddenLowConfidence": 0,
  "suppressed": 0,
  "ruleErrors": []
}
```

| Field | Meaning |
| --- | --- |
| `failed` | True when the exit code is 1 |
| `findings[]` | Shown findings, worst first. `severity` is `critical`, `high`, `medium` or `low`; `confidence` is `high`, `medium` or `low`. `file` is relative to the scanned folder, with forward slashes; `line` and `column` are 1-based. |
| `why`, `fix` | Plain-English explanation and fix |
| `fixPrompt` | A paste-ready prompt for an AI coding tool, when the rule has one |
| `hiddenLowConfidence` | Findings hidden by `--min-confidence` |
| `suppressed` | Findings silenced by `seaworthy-ignore` comments |
| `ruleErrors` | Rules that crashed and were skipped (the rest of the scan still ran) |
| `baseline` | Only with `--baseline`: `{ ref, sha, new, fixed, alreadyThere }` |

Secret values are never included: findings point at the file and line, not the key.

## Scheduled scans and alerts (Pro)

`npx seaworthy-cli init --schedule` writes `.github/workflows/seaworthy-scheduled.yml`, which scans every Monday (and whenever you press "Run workflow") and alerts when new problems appear. Scan history is kept between runs in the Actions cache, so "new" means new since the last run. That includes newly published advisories for dependencies you haven't changed.

Alerts are set up with environment variables (repository secrets in CI). Set at least one destination:

| Variable | Meaning |
| --- | --- |
| `SEAWORTHY_SLACK_WEBHOOK` | A Slack incoming-webhook URL |
| `SEAWORTHY_WEBHOOK_URL` | Any https URL; it receives a JSON POST with the title, counts and findings (rule, title, severity, file, line) |
| `SEAWORTHY_SMTP_URL` | Your own mail server: `smtps://user:password@smtp.example.com:465`, or `smtp://...:587` (STARTTLS is then required; Seaworthy won't send a password unencrypted). URL-encode special characters in the password. |
| `SEAWORTHY_EMAIL_TO` | With SMTP: one or more addresses, separated by commas |
| `SEAWORTHY_EMAIL_FROM` | With SMTP: the sender, if the username isn't an email address |

Alerts never include code, excerpts or secret values. If an alert can't be delivered, the run exits 2, so the failure shows. GitHub pauses scheduled workflows in repositories with no commits for 60 days; re-enable it in the Actions tab.

## Configuration

`seaworthy.config.json` in the scanned folder:

```json
{ "failOn": "high", "minConfidence": "high", "ignore": ["fixtures/**"], "rules": { "SW-B01": "off" }, "offline": false }
```

Silence one finding with a comment on the line, or the line above, giving a reason: `// seaworthy-ignore SW-S03 public demo key, rotated weekly`. A comment with no reason doesn't count.

## Using it with an AI coding assistant

Two options, both opt-in:

- **MCP server.** `seaworthy mcp` gives your assistant three tools: `scan_project`, `explain_finding` and `list_rules`. It runs locally over stdio.
  - Claude Code: `claude mcp add seaworthy -- npx -y seaworthy-cli mcp`
  - Cursor (`.cursor/mcp.json`) and Claude Desktop (`claude_desktop_config.json`): `{ "mcpServers": { "seaworthy": { "command": "npx", "args": ["-y", "seaworthy-cli", "mcp"] } } }`
- **A rules snippet.** `seaworthy init --agent` shows a short instruction for your assistant's rules file (AGENTS.md, CLAUDE.md, Cursor rules or Copilot instructions) and adds it only if you say yes. The snippets are also in `agent-rules/` in the source repo.

## Privacy

Seaworthy reads your files locally and never uploads code, findings or file names. Three things can use the network: the vulnerability check (SW-X01) sends package names and versions to osv.dev; the package-name check (SW-X02) sends package names only to the public npm registry (registry.npmjs.org), skipping the project's own workspace packages, packages from a private registry set in a `.npmrc` in the project (`registry=` for all packages, or `@scope:registry=` for one scope), and dependencies whose version starts with `file:`, `link:`, `workspace:`, `portal:`, `git:`, `git+…:` (such as `git+ssh:`), `github:`, `gitlab:`, `bitbucket:`, `http:` or `https:` (your user-level or global `.npmrc` isn't read, and any other dependency, such as a bare path like `../lib` or GitHub shorthand like `user/repo`, is looked up by name); and a paid licence is checked with the licence server at most once a day (key, machine name and licence IDs only). `--offline` skips both dependency lookups. There is no telemetry.
