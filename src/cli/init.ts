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
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
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
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: seaworthy.sarif
          category: seaworthy
      - name: Fail on findings at or above the threshold
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
export function initProject(dir: string, force: boolean): { created: string[]; skipped: string[] } {
  const files: Array<[string, string]> = [
    [join(dir, "seaworthy.config.json"), CONFIG],
    [join(dir, ".github", "workflows", "seaworthy.yml"), WORKFLOW],
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
