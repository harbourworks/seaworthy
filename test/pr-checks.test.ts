import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";
import { PURCHASE_URL } from "../src/licensing/config.js";
import { extractBaseline } from "../src/core/baseline.js";
import { diffFindings } from "../src/pro/compare.js";
import { code, text } from "../src/reporters/markdown.js";
import { PR_WORKFLOW } from "../src/cli/init.js";
import type { Finding } from "../src/core/finding.js";

const NOTES_SAAS = resolve(__dirname, "../fixtures/apps/notes-saas");
const PRO_KEY = "SEAWORTHY-TEST-PRO-0001";
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

let work: string;
let provider: MockProvider;

/** OSV with no known vulnerabilities, so these tests never touch the network. */
const quietOsv = (async (url: string, init?: RequestInit) => {
  if (!url.endsWith("/querybatch")) return new Response("{}", { status: 404 });
  const { queries } = JSON.parse(String(init!.body)) as { queries: unknown[] };
  return new Response(JSON.stringify({ results: queries.map(() => ({})) }));
}) as unknown as typeof fetch;

function cli(env: NodeJS.ProcessEnv = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const deps: CliDeps = {
    out: (s) => out.push(strip(s)),
    err: (s) => err.push(strip(s)),
    env: { SEAWORTHY_CONFIG_DIR: join(work, "config"), ...env },
    cwd: work,
    now: () => new Date("2026-11-10T09:00:00Z"),
    provider,
    fetch: quietOsv,
  };
  return { out, err, all: () => [...out, ...err].join("\n"), run: (...argv: string[]) => run(argv, deps) };
}
const pro = () => cli({ SEAWORTHY_LICENCE: PRO_KEY });

function git(cwd: string, ...args: string[]): string {
  return execFileSync(
    "git",
    ["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-C", cwd, ...args],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

const MIGRATION = "supabase/migrations/0001_init.sql";

/**
 * A repo whose `main` is notes-saas with two differences, then a `feature` branch that:
 *  - removes `enable row level security` on payments (SW-D01, critical: new),
 *  - deletes the search route (SW-A05: fixed),
 *  - adds lines above the Stripe key (SW-S01 moves line: still the same finding).
 */
function makeRepo(sub = ""): { repo: string; app: string } {
  const repo = join(work, "repo");
  const app = sub ? join(repo, sub) : repo;
  mkdirSync(app, { recursive: true });
  cpSync(NOTES_SAAS, app, { recursive: true });
  git(repo, "init", "--quiet", "-b", "main");
  const sql = readFileSync(join(app, MIGRATION), "utf8");
  writeFileSync(join(app, MIGRATION), sql + "\nalter table public.payments enable row level security;\n");
  git(repo, "add", "-A", "-f"); // the fixture commits its .env on purpose
  git(repo, "commit", "--quiet", "-m", "base");

  git(repo, "checkout", "--quiet", "-b", "feature");
  writeFileSync(join(app, MIGRATION), sql);
  rmSync(join(app, "app/api/search/route.ts"));
  const stripe = join(app, "lib/stripe.ts");
  writeFileSync(stripe, "// Payments\n// (moved down two lines)\n" + readFileSync(stripe, "utf8"));
  git(repo, "add", "-A", "-f");
  git(repo, "commit", "--quiet", "-m", "feature");
  return { repo, app };
}

beforeEach(() => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-pr-"));
  provider = new MockProvider().addKey(PRO_KEY, "pro");
});
afterEach(() => rmSync(work, { recursive: true, force: true }));

describe("pull-request checks: the engine", () => {
  it("reports only what the change introduces, lists what it fixed, and counts the rest", async () => {
    const { app } = makeRepo();
    const c = pro();
    expect(await c.run("scan", app, "--baseline", "main", "--format", "json")).toBe(1);
    const j = JSON.parse(c.out.join("\n"));
    expect(j.baseline.ref).toBe("main");
    expect(j.baseline.sha).toMatch(/^[0-9a-f]{40}$/);
    expect(j.baseline.new.map((f: Finding) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual([`SW-D01 ${MIGRATION}:20`]);
    expect(j.baseline.fixed.map((f: Finding) => `${f.ruleId} ${f.file}`)).toEqual(["SW-A05 app/api/search/route.ts"]);
    // Everything else, including the moved Stripe key and the committed .env (SW-S02 asks git), is already there.
    expect(j.baseline.alreadyThere).toBe(j.findings.length - 1);
    expect(j.findings.some((f: Finding) => f.ruleId === "SW-S02" && f.file === ".env")).toBe(true);
    expect(j.failed).toBe(true);
  });

  it("passes when the change adds nothing at or above failOn, even though old problems remain", async () => {
    const { repo, app } = makeRepo();
    git(repo, "checkout", "--quiet", "-b", "docs", "main");
    writeFileSync(join(app, "README.md"), "# Notes\n");
    const c = pro();
    expect(await c.run("scan", app, "--baseline", "main")).toBe(0);
    expect(c.all()).toMatch(/No new problems since main/);
    expect(c.all()).toMatch(/0 fixed\s+·\s+\d+ already there/);
  });

  it("new findings below the threshold are shown but don't fail", async () => {
    const { repo, app } = makeRepo();
    git(repo, "checkout", "--quiet", "-b", "search2", "main");
    mkdirSync(join(app, "app/api/search2"));
    cpSync(join(app, "app/api/search/route.ts"), join(app, "app/api/search2/route.ts"));
    const c = pro();
    expect(await c.run("scan", app, "--baseline", "main", "--fail-on", "critical", "--format", "json")).toBe(0);
    const j = JSON.parse(c.out.join("\n"));
    expect(j.baseline.new.map((f: Finding) => `${f.ruleId} ${f.severity} ${f.file}`)).toEqual(["SW-A05 high app/api/search2/route.ts"]);
    expect(j.failed).toBe(false);
    const t = pro();
    expect(await t.run("scan", app, "--baseline", "main", "--fail-on", "critical")).toBe(0);
    expect(t.all()).toMatch(/No new problems at or above critical \(1 high new, below your threshold\)/);
  });

  it("works on a project inside a bigger repo, and treats a folder that's new in the change as all new", async () => {
    const { repo, app } = makeRepo("apps/web");
    const c = pro();
    expect(await c.run("scan", app, "--baseline", "main", "--format", "json")).toBe(1);
    expect(JSON.parse(c.out.join("\n")).baseline.new.map((f: Finding) => f.ruleId)).toEqual(["SW-D01"]);

    // A project that didn't exist on the base: every finding is new.
    const other = join(repo, "apps/other");
    cpSync(NOTES_SAAS, other, { recursive: true });
    git(repo, "add", "-A", "-f");
    git(repo, "commit", "--quiet", "-m", "another app");
    const c2 = pro();
    expect(await c2.run("scan", other, "--baseline", "main", "--format", "json")).toBe(1);
    const j2 = JSON.parse(c2.out.join("\n"));
    expect(j2.baseline.new.length).toBe(j2.findings.length);
    expect(j2.baseline.alreadyThere).toBe(0);
  });

  it("leaves the repo exactly as it was and cleans up after itself", async () => {
    const { repo, app } = makeRepo();
    writeFileSync(join(app, "untracked.txt"), "work in progress\n");
    const before = { status: git(repo, "status", "--porcelain"), worktrees: git(repo, "worktree", "list"), refs: git(repo, "show-ref"), head: git(repo, "rev-parse", "HEAD") };
    const temps = () => readdirSync(tmpdir()).filter((n) => n.startsWith("seaworthy-baseline-")).length;
    const t0 = temps();
    await pro().run("scan", app, "--baseline", "main", "--format", "json");
    expect({ status: git(repo, "status", "--porcelain"), worktrees: git(repo, "worktree", "list"), refs: git(repo, "show-ref"), head: git(repo, "rev-parse", "HEAD") }).toEqual(before);
    expect(temps()).toBeLessThanOrEqual(t0);
  });

  it("never runs the repo's hooks or filters while reading the base", async () => {
    const { repo } = makeRepo();
    const marker = join(work, "ran");
    const cmd = `node -e "require('fs').writeFileSync(process.argv[1], 'x')" "${marker.replace(/\\/g, "/")}"`;
    git(repo, "config", "filter.evil.smudge", cmd);
    git(repo, "config", "core.fsmonitor", cmd);
    writeFileSync(join(repo, ".git", "hooks", "post-checkout"), `#!/bin/sh\n${cmd}\n`, { mode: 0o755 });
    writeFileSync(join(repo, ".gitattributes"), "* filter=evil\n");
    git(repo, "-c", "core.fsmonitor=false", "add", ".gitattributes");
    git(repo, "-c", "core.fsmonitor=false", "commit", "--quiet", "--no-verify", "-m", "attrs");
    const b = extractBaseline(repo, "HEAD");
    try {
      expect(existsSync(join(b.dir, "package.json"))).toBe(true);
      expect(existsSync(marker)).toBe(false);
    } finally {
      b.cleanup();
    }
    // Control: the trap is real. An ordinary checkout runs the smudge filter.
    rmSync(join(repo, "package.json"));
    git(repo, "-c", "core.fsmonitor=false", "checkout", "HEAD", "--", "package.json");
    expect(existsSync(marker)).toBe(true);
  });

  it("explains a missing ref or a folder outside git, with exit code 2", async () => {
    const { app } = makeRepo();
    const c = pro();
    expect(await c.run("scan", app, "--baseline", "origin/nope")).toBe(2);
    expect(c.all()).toMatch(/Couldn't find origin\/nope.*fetch-depth: 0/);

    const outside = mkdtempSync(join(tmpdir(), "seaworthy-nogit-"));
    try {
      cpSync(NOTES_SAAS, outside, { recursive: true });
      const c2 = pro();
      expect(await c2.run("scan", outside, "--baseline", "main")).toBe(2);
      expect(c2.all()).toMatch(/needs a git repository/);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }

    const c3 = pro();
    expect(await c3.run("scan", app, "--baseline", "main", "--all")).toBe(2);
    expect(c3.all()).toMatch(/can't be combined with --all/);
  });
});

describe("pull-request checks: gating", () => {
  it("without Pro: a normal full scan, the normal exit code and one upsell line", async () => {
    const { app } = makeRepo();
    const c = cli();
    expect(await c.run("scan", app, "--baseline", "main")).toBe(1);
    expect(c.all()).toMatch(/Not seaworthy/);
    expect(c.all()).not.toMatch(/Compared with/);
    const upsells = c.all().split("\n").filter((l) => l.includes(PURCHASE_URL));
    expect(upsells).toHaveLength(1);
    expect(upsells[0]).toMatch(/Ran a full scan instead\. Seaworthy Pro .* unlocks pull-request checks that show only new problems/);
  });

  it("without Pro, the Markdown summary is the full scan and carries the upsell", async () => {
    const { app } = makeRepo();
    expect(await cli().run("scan", app, "--baseline", "main", "--format", "markdown")).toBe(1);
    const md = readFileSync(join(work, "seaworthy-report.md"), "utf8");
    expect(md).toMatch(/^<!-- seaworthy -->/);
    expect(md).toContain("### ✖ Not seaworthy");
    expect(md).toContain(PURCHASE_URL);
    expect(md).not.toMatch(/\x1b\[/);
  });
});

describe("pull-request checks: the comment", () => {
  it("new problems in full with a masked excerpt, fixed ones listed, existing ones counted, no secrets", async () => {
    const { app } = makeRepo();
    const env = {
      SEAWORTHY_LICENCE: PRO_KEY,
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "acme/notes",
      GITHUB_SHA: "a".repeat(40),
      GITHUB_WORKSPACE: app,
    };
    expect(await cli(env).run("scan", app, "--baseline", "main", "--format", "markdown", "--output", "pr.md")).toBe(1);
    const md = readFileSync(join(work, "pr.md"), "utf8");
    expect(md.startsWith("<!-- seaworthy-pr-check -->\n")).toBe(true);
    expect(md).toContain("### ✖ Seaworthy: 1 new problem in this pull request (1 critical)");
    expect(md).toMatch(/Compared with `main` \(`[0-9a-f]{7}`\)\. \*\*1 problem fixed\.\*\* \d+ problems already there before this change are not repeated here\./);
    expect(md).toContain("#### 🔴 Critical");
    expect(md).toContain(`[\`${MIGRATION}:20\`](https://github.com/acme/notes/blob/${"a".repeat(40)}/supabase/migrations/0001_init.sql#L20)`);
    expect(md).toMatch(/> 20 │ create table public\.payments/);
    expect(md).toContain("**Why**");
    expect(md).toContain("<details><summary>✔ 1 problem fixed by this change</summary>");
    expect(md).toContain("`app/api/search/route.ts:13`");
    expect(md).toMatch(/Already there before this change: \d+ critical/);
    // Only the new finding is shown in full: no excerpt from the files that already had problems.
    expect(md).not.toContain("lib/stripe.ts");
    const dotenv = readFileSync(join(app, ".env"), "utf8");
    for (const m of dotenv.matchAll(/=(\S{20,})$/gm)) expect(md).not.toContain(m[1]!);
  });

  it("says so plainly when there is nothing new", async () => {
    const { repo, app } = makeRepo();
    git(repo, "checkout", "--quiet", "main");
    expect(await pro().run("scan", app, "--baseline", "main", "--format", "markdown")).toBe(0);
    const md = readFileSync(join(work, "seaworthy-report.md"), "utf8");
    expect(md).toContain("### ✔ Seaworthy: no new problems in this pull request");
    expect(md).not.toContain("####");
  });

  it("text from scanned code can't add HTML, images, links or @mentions", () => {
    expect(text("Table <img src=x onerror=alert(1)> is open")).toBe("Table &lt;img src=x onerror=alert(1)&gt; is open");
    expect(text("![x](https://evil.example/p.png) [click](https://evil.example)")).not.toMatch(/(?<!\\)!\[|(?<!\\)\]\(/);
    expect(text("ping @octocat")).toBe("ping @&#8203;octocat");
    expect(text("use `auth.uid()` here")).toBe("use `auth.uid()` here");
    expect(text("a | b")).toBe("a \\| b");
    expect(code("odd`name")).toBe("``odd`name``");
  });
});

describe("pull-request checks: matching", () => {
  const f = (ruleId: string, file: string, line: number): Finding =>
    ({ ruleId, file, line, column: 1, severity: "high", confidence: "high", title: ruleId, why: "", fix: "" }) as Finding;
  it("pairs by rule and file in line order, so moved code isn't new", () => {
    const d = diffFindings([f("A", "x.ts", 10), f("A", "x.ts", 20), f("B", "y.ts", 1)], [f("A", "x.ts", 15), f("A", "x.ts", 30), f("A", "x.ts", 40), f("C", "z.ts", 2)]);
    expect(d.stillPresent.map((x) => x.line)).toEqual([15, 30]);
    expect(d.added.map((x) => `${x.ruleId}:${x.line}`).sort()).toEqual(["A:40", "C:2"]);
    expect(d.fixed.map((x) => x.ruleId)).toEqual(["B"]);
  });
});

describe("init --pr", () => {
  it("writes the pull-request workflow", async () => {
    const dir = join(work, "fresh");
    mkdirSync(dir);
    const c = cli();
    expect(await c.run("init", dir, "--pr")).toBe(0);
    const wf = readFileSync(join(dir, ".github", "workflows", "seaworthy.yml"), "utf8");
    expect(wf).toBe(PR_WORKFLOW);
    expect(wf).toContain("fetch-depth: 0");
    expect(wf).toContain('--baseline "origin/$BASE_REF" --format markdown --output seaworthy-pr.md');
    expect(wf).toContain("BASE_REF: ${{ github.base_ref }}");
    expect(wf).toContain("pull-requests: write");
    expect(wf).toContain("SEAWORTHY_LICENCE: ${{ secrets.SEAWORTHY_LICENCE }}");
    expect(wf).toContain("updateComment");
    // The branch name is passed through the environment, never pasted into the shell command.
    expect(wf).not.toMatch(/run: .*\$\{\{/);
    expect(c.all()).toContain("SEAWORTHY_LICENCE");
  });

  it("an empty SEAWORTHY_LICENCE (no secret set) is Free, not an error", async () => {
    const { app } = makeRepo();
    const c = cli({ SEAWORTHY_LICENCE: "" });
    expect(await c.run("scan", app, "--baseline", "main")).toBe(1);
    expect(c.all()).toMatch(/Ran a full scan instead/);
    expect(provider.calls).toEqual([]);
  });
});
