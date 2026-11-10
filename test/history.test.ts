import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { RULES } from "../src/rules/index.js";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
/** A random, real-looking Stripe live key, built at runtime so none is committed to this repo. */
const stripeKey = () => "sk_" + "live_" + "51" + randomBytes(40).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 96);

let repo: string;
let cfg: string;
const git = (...args: string[]) =>
  execFileSync("git", ["-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-C", repo, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
const commit = (msg: string) => {
  git("add", "-A");
  git("commit", "--quiet", "-m", msg);
  return git("rev-parse", "--short", "HEAD");
};
const write = (p: string, c: string) => {
  mkdirSync(join(repo, p, ".."), { recursive: true });
  writeFileSync(join(repo, p), c);
};
const history = (root = repo) => scan(root, DEFAULT_CONFIG, RULES).findings.filter((f) => f.ruleId === "SW-S01");

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), "seaworthy-hist-"));
  cfg = mkdtempSync(join(tmpdir(), "seaworthy-hist-cfg-"));
  git("init", "--quiet", "-b", "main");
  write("README.md", "# app\n");
  commit("init");
});
afterEach(() => {
  rmSync(repo, { recursive: true, force: true });
  rmSync(cfg, { recursive: true, force: true });
});

describe("SW-S01 in git history", () => {
  it("finds a key that was committed and later deleted, with the commit that added it", () => {
    write("lib/stripe.ts", `import Stripe from "stripe";\n\nexport const stripe = new Stripe("${stripeKey()}");\n`);
    const added = commit("add stripe");
    rmSync(join(repo, "lib/stripe.ts"));
    commit("remove the key");

    const f = history();
    expect(f.map((x) => `${x.file}:${x.line} ${x.severity} ${x.title} ${x.commit}`)).toEqual([
      `lib/stripe.ts:3 critical Stripe live secret key in git history ${added}`,
    ]);
    expect(f[0]!.why).toContain(`It was committed in ${added}`);
    expect(f[0]!.fix).toMatch(/^Roll the key in the provider's dashboard \(Stripe: Developers → API keys\)\. Removing the file doesn't remove it from history/);
  });

  it("reports a key that's still in the files once, as a current finding", () => {
    const key = stripeKey();
    write("lib/stripe.ts", `export const stripe = new Stripe("${key}");\n`);
    commit("add");
    write("lib/stripe.ts", `// payments\nexport const stripe = new Stripe("${key}");\n`); // a new version of the file, same key
    commit("tweak");
    const f = history();
    expect(f).toHaveLength(1);
    expect(f[0]!.commit).toBeUndefined();
    expect(f[0]!.line).toBe(2);
  });

  it("runs only for the repository's top folder, and respects the config's ignore patterns", () => {
    write("apps/web/keys.ts", `const k = "${stripeKey()}";\n`);
    write("fixtures/fake.ts", `const k = "${stripeKey()}";\n`);
    commit("add");
    rmSync(join(repo, "apps/web/keys.ts"));
    rmSync(join(repo, "fixtures/fake.ts"));
    write("apps/web/index.ts", "export {};\n");
    commit("remove");
    expect(history(join(repo, "apps/web"))).toEqual([]);
    const ignored = scan(repo, { ...DEFAULT_CONFIG, ignore: ["fixtures/**"] }, RULES).findings.filter((f) => f.ruleId === "SW-S01");
    expect(ignored.map((f) => f.file)).toEqual(["apps/web/keys.ts"]);
  });

  it("shows the commit instead of an excerpt, and JSON carries it", async () => {
    write("config.ts", `export const key = "${stripeKey()}";\n`);
    const added = commit("add");
    write("config.ts", "export const key = process.env.STRIPE_SECRET_KEY;\n");
    commit("use env");
    const out: string[] = [];
    const err: string[] = [];
    const deps: CliDeps = { out: (s) => out.push(strip(s)), err: (s) => err.push(strip(s)), env: { SEAWORTHY_CONFIG_DIR: cfg }, cwd: repo, now: () => new Date(), provider: new MockProvider() };
    await run([repo, "--offline"], deps);
    const text = out.join("\n");
    expect(text).toContain(`config.ts:1:21  in commit ${added}`);
    expect(text).not.toMatch(/> 1 │ export const key = process\.env/); // today's line isn't shown as the leak
    out.length = 0;
    await run([repo, "--offline", "--format", "json"], deps); // JSON on stdout, notes on stderr
    const json = JSON.parse(out.join("\n"));
    expect(json.findings.find((f: { ruleId: string }) => f.ruleId === "SW-S01").commit).toBe(added);
  });

  it("in a pull-request check, an old leak isn't new, but one added and removed in the PR is", async () => {
    write("old.ts", `const k = "${stripeKey()}";\n`);
    commit("old leak");
    rmSync(join(repo, "old.ts"));
    commit("clean up");
    git("checkout", "--quiet", "-b", "feature");
    write("new.ts", `const k = "${stripeKey()}";\n`);
    const leaked = commit("oops");
    rmSync(join(repo, "new.ts"));
    commit("remove it");

    const out: string[] = [];
    const deps: CliDeps = {
      out: (s) => out.push(strip(s)),
      err: () => {}, // notes; the JSON is on stdout
      env: { SEAWORTHY_CONFIG_DIR: cfg, SEAWORTHY_LICENCE: "SEAWORTHY-TEST-PRO-0001" },
      cwd: repo,
      now: () => new Date(),
      provider: new MockProvider().addKey("SEAWORTHY-TEST-PRO-0001", "pro"),
      fetch: (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch,
    };
    expect(await run([repo, "--baseline", "main", "--format", "json"], deps)).toBe(1);
    const j = JSON.parse(out.join("\n"));
    expect(j.baseline.new.map((f: { file: string; commit: string }) => `${f.file} ${f.commit}`)).toEqual([`new.ts ${leaked}`]);
    expect(j.baseline.alreadyThere).toBe(1);
  });
});
