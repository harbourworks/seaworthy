# Seaworthy plans

The tier-to-feature mapping in code lives in one place: `src/core/entitlements.ts`. This page describes it; if they ever disagree, the code wins and this page is out of date.

| | Free | Pro | Agency |
| --- | --- | --- | --- |
| Price | £0 | £12 / month or £99 / year | £349 / year |
| Every check, local CLI, GitHub Action | ✔ | ✔ | ✔ |
| Terminal, JSON, SARIF and Markdown output, exit codes for CI | ✔ | ✔ | ✔ |
| Fix text and paste-ready AI prompts | ✔ | ✔ | ✔ |
| Pull-request checks: only new problems, one updated comment (`--baseline <ref>`, `init --pr`) | | ✔ | ✔ |
| HTML report (`--format html`), Seaworthy-branded | | ✔ | ✔ |
| Scan history and trends (`seaworthy history`) | | ✔ | ✔ |
| Before/after comparison (`seaworthy compare`, plus "since last scan" on every scan) | | ✔ | ✔ |
| White-label reports: your logo, agency name and client name | | | ✔ |
| Scan every project in a folder, one combined report (`scan <folder> --all`) | | | ✔ |
| Machines per key | n/a | 2 | 10 |

Founding-member pricing at launch is a Polar discount, not a code change. Monthly and yearly Pro use the same licence-key benefit, so they unlock the same features.

**Free is never blocked or degraded.** Using a paid feature without the right plan still runs the scan with terminal output and the normal exit code, and prints one line naming the plan that unlocks it.

## Buying and using a licence

```
seaworthy buy             # the plans, and the checkout opened in your browser
seaworthy login           # (no key) where to find it: the portal, opened in your browser
seaworthy login <key>     # activates this machine (uses one of its slots)
seaworthy status          # plan, key (masked), machine, last check, offline grace
seaworthy logout          # frees this machine's slot
```

- **Your key** is in the customer portal, https://polar.sh/dynamo-maritime/portal: enter the email you bought with, type the verification code Polar sends, and copy the key under your plan. Every message that mentions the key links there (`PORTAL_URL` in `src/licensing/config.ts`).
- Links open in the browser only for a person at a terminal: never in CI, never when output is piped, and never with `--no-open`.
- The licence is saved in your user config folder (`%APPDATA%\seaworthy` on Windows, `~/Library/Application Support/seaworthy` on macOS, `~/.config/seaworthy` on Linux), never in a project.
- **CI:** set `SEAWORTHY_LICENCE` to the key. It takes priority over a saved login and does not use up a machine slot per run.
- **What is sent:** only the licence key, the machine label (your computer's name, or `--label`) and the IDs the licence server issued. Never code, findings or file names.
- **When:** only if you have a licence, and at most once a day. Free users' scans make no licence calls at all.
- **Offline:** a confirmed licence keeps working for 14 days without a connection, and `--offline` never calls the server. After 14 days unconfirmed, paid features pause until Seaworthy can check online; scanning itself never stops.
- **When a subscription ends,** the key stops validating and Seaworthy goes back to Free with a message saying how to renew.

## White-label settings (Agency)

In `seaworthy.config.json`, in the folder you scan (for `--all`, the top folder):

```json
{
  "report": {
    "agencyName": "Northlight Studio",
    "clientName": "Harbour Bakery Ltd",
    "logo": "branding/logo.svg"
  }
}
```

The logo can be PNG, JPEG, WebP or SVG, up to 512 KB, and is embedded in the report so it stays a single file.

## Licences

- **Free scanner:** Functional Source License 1.1 with an Apache 2.0 future licence (`LICENSE`). Anyone may use it for any purpose except a competing product or service, including at work, for clients and in CI. Each release becomes Apache 2.0 two years after it is published.
- **Paid features (`src/pro/`):** Seaworthy Commercial Licence (`LICENSE-COMMERCIAL.md`). They need a valid key for a plan that includes them, and the licence check must not be bypassed. The package itself can still be installed and mirrored freely.

## Pull-request checks

`seaworthy --baseline <ref>` scans the base ref and the working tree with the same config (the working tree's, so a change can't loosen its own check), then matches findings by rule and file, paired in line order, so code that only moved isn't reported as new.

- **The base is read, not checked out.** Its files come straight from git's object store into a temporary folder, so no hooks, filters or `core.fsmonitor` run, and your repo, index and worktrees are left exactly as they were.
- **In GitHub Actions** (`seaworthy init --pr`): `fetch-depth: 0`, `--baseline "origin/$BASE_REF" --format markdown`, the summary added to the run, and one pull-request comment found by a hidden marker and updated on each push. It needs `pull-requests: write`. Pull requests from forks get a read-only token and no secrets, so they get the run summary and a full scan, not a comment.
- **The comment** shows new problems in full, with the same masked three-line excerpt as the terminal; fixed problems as one line each (no code); and problems already there as counts only. Text that comes from the scanned code is escaped, so it can't add HTML, images, links or @mentions.
- **Exit code:** 1 only for new findings at or above `failOn`.

## What reports and history contain

- **HTML reports** are single self-contained files with no scripts or external resources. Secrets in code excerpts are always masked. Every report says: *"Automated scan results. Not a security certification or a guarantee."*
- **History** is stored in `<project>/.seaworthy/history.json`, which Seaworthy git-ignores automatically. It holds metadata only: rule, file, line, severity and time. Never code, titles or secrets. Turn it off for one scan with `--no-history`.
