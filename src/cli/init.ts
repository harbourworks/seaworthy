import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

/** The workflow `seaworthy init` writes. Pinned to major versions; npx always takes the latest 0.x. */
export const WORKFLOW = `# Seaworthy: pre-launch security check. https://dynamomaritime.com/seaworthy
name: Seaworthy

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # to show findings in the Security tab and on pull requests

jobs:
  seaworthy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - name: Scan
        id: scan
        continue-on-error: true
        run: npx --yes seaworthy-cli@0 --format sarif --output seaworthy.sarif
        # Pro or Agency? Add your key as a repository secret and uncomment:
        # env:
        #   SEAWORTHY_LICENCE: \${{ secrets.SEAWORTHY_LICENCE }}
      - name: Upload results to GitHub code scanning
        if: always() && hashFiles('seaworthy.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: seaworthy.sarif
          category: seaworthy
      - name: Fail on findings at or above the threshold
        if: always() && steps.scan.outcome == 'failure'
        run: exit 1
`;

/**
 * The workflow `seaworthy init --pr` writes (Pro). Pushes to main upload SARIF as above.
 * Pull requests scan the base branch and the change, and post one comment listing only
 * what the change introduces, updated in place on every push.
 */
export const PR_WORKFLOW = `# Seaworthy: pre-launch security check. https://dynamomaritime.com/seaworthy
# Pull requests get one comment listing only the problems they introduce (Seaworthy Pro).
# Add your licence key as a repository secret called SEAWORTHY_LICENCE. Without it, pull
# requests get a full scan instead.
name: Seaworthy

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # to show findings in the Security tab
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - name: Scan
        id: scan
        continue-on-error: true
        run: npx --yes seaworthy-cli@0 --format sarif --output seaworthy.sarif
        env:
          SEAWORTHY_LICENCE: \${{ secrets.SEAWORTHY_LICENCE }}
      - name: Upload results to GitHub code scanning
        if: always() && hashFiles('seaworthy.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: seaworthy.sarif
          category: seaworthy
      - name: Fail on findings at or above the threshold
        if: always() && steps.scan.outcome == 'failure'
        run: exit 1

  pull-request:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # to post and update the comment
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # the base branch is needed to compare with
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - name: Scan what this pull request changes
        id: scan
        continue-on-error: true
        run: npx --yes seaworthy-cli@0 --baseline "origin/$BASE_REF" --format markdown --output seaworthy-pr.md
        env:
          BASE_REF: \${{ github.base_ref }}
          SEAWORTHY_LICENCE: \${{ secrets.SEAWORTHY_LICENCE }}
      - name: Add the summary to this run
        if: always() && hashFiles('seaworthy-pr.md') != ''
        run: cat seaworthy-pr.md >> "$GITHUB_STEP_SUMMARY"
      - name: Comment on the pull request
        if: always() && hashFiles('seaworthy-pr.md') != ''
        continue-on-error: true # pull requests from forks get a read-only token
        uses: actions/github-script@v9
        with:
          script: |
            const body = require("fs").readFileSync("seaworthy-pr.md", "utf8");
            const marker = /<!-- seaworthy(-pr-check)? -->/;
            const { owner, repo } = context.repo;
            const issue_number = context.issue.number;
            const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number, per_page: 100 });
            const mine = comments.find((c) => c.user && c.user.type === "Bot" && marker.test(c.body || ""));
            if (mine) await github.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body });
            else await github.rest.issues.createComment({ owner, repo, issue_number, body });
      - name: Fail on new findings at or above the threshold
        if: always() && steps.scan.outcome == 'failure'
        run: exit 1
`;

/**
 * The workflow `seaworthy init --schedule` writes (Pro): a weekly scan that alerts when
 * something new appears. Scan history is carried between runs in the Actions cache, so
 * "new" means new since last week, including fresh vulnerability advisories for code that
 * hasn't changed.
 */
export const SCHEDULE_WORKFLOW = `# Seaworthy: weekly security scan with alerts (Seaworthy Pro). https://dynamomaritime.com/seaworthy
# Add these repository secrets (Settings, then Secrets and variables, then Actions):
#   SEAWORTHY_LICENCE        your Pro or Agency key
#   and at least one of:
#   SEAWORTHY_SLACK_WEBHOOK  a Slack incoming-webhook URL
#   SEAWORTHY_WEBHOOK_URL    any https URL that accepts a JSON POST
#   SEAWORTHY_SMTP_URL       smtps://user:password@smtp.example.com:465, plus SEAWORTHY_EMAIL_TO
# Alerts list rule, file and line only: never code or secrets.
name: Seaworthy weekly scan

on:
  schedule:
    - cron: "17 7 * * 1" # Mondays at 07:17 UTC
  workflow_dispatch: # and whenever you press "Run workflow"

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - name: Restore scan history
        uses: actions/cache/restore@v6
        with:
          path: .seaworthy
          key: seaworthy-history-\${{ github.run_id }}
          restore-keys: seaworthy-history-
      - name: Scan and alert
        id: scan
        continue-on-error: true
        run: npx --yes seaworthy-cli@0 --notify --format markdown --output seaworthy-report.md
        env:
          SEAWORTHY_LICENCE: \${{ secrets.SEAWORTHY_LICENCE }}
          SEAWORTHY_SLACK_WEBHOOK: \${{ secrets.SEAWORTHY_SLACK_WEBHOOK }}
          SEAWORTHY_WEBHOOK_URL: \${{ secrets.SEAWORTHY_WEBHOOK_URL }}
          SEAWORTHY_SMTP_URL: \${{ secrets.SEAWORTHY_SMTP_URL }}
          SEAWORTHY_EMAIL_TO: \${{ secrets.SEAWORTHY_EMAIL_TO }}
          SEAWORTHY_EMAIL_FROM: \${{ secrets.SEAWORTHY_EMAIL_FROM }}
      - name: Add the report to this run
        if: always() && hashFiles('seaworthy-report.md') != ''
        run: cat seaworthy-report.md >> "$GITHUB_STEP_SUMMARY"
      - name: Save scan history
        if: always() && hashFiles('.seaworthy/history.json') != ''
        uses: actions/cache/save@v6
        with:
          path: .seaworthy
          key: seaworthy-history-\${{ github.run_id }}
      - name: Fail on findings or a failed alert
        if: always() && steps.scan.outcome == 'failure'
        run: exit 1
`;

export const CONFIG = `${JSON.stringify(
  {
    failOn: "high",
    minConfidence: "high",
    ignore: [],
    rules: {},
  },
  null,
  2,
)}\n`;

/** Writes the config and workflow, never overwriting what's there unless forced. Returns lines to print. */
export function initProject(dir: string, force: boolean, opts: { pr?: boolean; schedule?: boolean } = {}): { created: string[]; skipped: string[] } {
  const files: Array<[string, string]> = [
    [join(dir, "seaworthy.config.json"), CONFIG],
    opts.schedule
      ? [join(dir, ".github", "workflows", "seaworthy-scheduled.yml"), SCHEDULE_WORKFLOW]
      : [join(dir, ".github", "workflows", "seaworthy.yml"), opts.pr ? PR_WORKFLOW : WORKFLOW],
  ];
  const created: string[] = [];
  const skipped: string[] = [];
  for (const [path, content] of files) {
    const rel = relative(dir, path).replace(/\\/g, "/");
    if (existsSync(path) && !force) {
      skipped.push(rel);
      continue;
    }
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    created.push(rel);
  }
  return { created, skipped };
}
