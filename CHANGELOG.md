# Changelog

All notable changes to seaworthy-cli. Versions follow [semantic versioning](https://semver.org); while it's 0.x, a minor version can change behaviour.

## Unreleased

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
