import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";
import { PURCHASE_URL } from "../src/licensing/config.js";
import { DISCLAIMER } from "../src/pro/html.js";
import { RULES } from "../src/rules/index.js";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";

/** How many findings a plain scan of a copied test app shows, so counts follow the rules as they grow. */
const findingCount = (dir: string) => scan(dir, DEFAULT_CONFIG, RULES).findings.length;

const FIXTURES = resolve(__dirname, "../fixtures/apps");
const PRO_KEY = "SEAWORTHY-TEST-PRO-0001";
const AGENCY_KEY = "SEAWORTHY-TEST-AGENCY-0001";
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

let work: string;
let provider: MockProvider;
let clock: Date;

function cli() {
  const out: string[] = [];
  const err: string[] = [];
  const deps: CliDeps = {
    out: (s) => out.push(strip(s)),
    err: (s) => err.push(strip(s)),
    env: { SEAWORTHY_CONFIG_DIR: join(work, "config") },
    cwd: work,
    now: () => clock,
    provider,
  };
  return { deps, out, err, all: () => [...out, ...err].join("\n"), run: (...argv: string[]) => run(argv, deps) };
}

/** Copies fixture apps into a temp folder, so history and reports never touch the repo. */
function copyApps(): string {
  const dest = join(work, "clients");
  cpSync(FIXTURES, dest, { recursive: true });
  return dest;
}

beforeEach(() => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-cli-"));
  provider = new MockProvider().addKey(PRO_KEY, "pro").addKey(AGENCY_KEY, "agency");
  clock = new Date("2026-11-10T09:00:00Z");
});
afterEach(() => rmSync(work, { recursive: true, force: true }));

describe("Free is never blocked or degraded", () => {
  it("scans normally, with the normal exit code and no licence calls", async () => {
    const apps = copyApps();
    const c = cli();
    expect(await c.run(join(apps, "notes-saas"))).toBe(1);
    expect(c.all()).toMatch(/Not seaworthy/);
    expect(provider.calls).toEqual([]);
    expect(existsSync(join(apps, "notes-saas", ".seaworthy"))).toBe(false); // no history for Free
  });

  it("locked features: still scans with terminal output, one friendly line, normal exit code", async () => {
    const apps = copyApps();
    for (const [args, unlock] of [
      [["--format", "html"], "Pro"],
      [["--all"], "Agency"],
    ] as const) {
      const c = cli();
      const code = await c.run(join(apps, "notes-saas"), ...args);
      expect(code).toBe(1);
      expect(c.all()).toMatch(/Not seaworthy/);
      const lines = c.all().split("\n").filter((l) => l.includes("✦"));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain(`Seaworthy ${unlock}`);
      expect(lines[0]).toContain(PURCHASE_URL);
    }
    expect(existsSync(join(work, "seaworthy-report.html"))).toBe(false);
  });

  it("history and compare without Pro fall back to a normal scan", async () => {
    const apps = copyApps();
    for (const cmd of ["history", "compare"]) {
      const c = cli();
      expect(await c.run(cmd, join(apps, "chat-agent"))).toBe(1);
      expect(c.all()).toMatch(/Not seaworthy/);
      expect(c.all()).toContain("Seaworthy Pro (£12/month or £99/year) unlocks");
    }
  });

  it("JSON output stays valid JSON: notes go to stderr", async () => {
    const apps = copyApps();
    const c = cli();
    await c.run(join(apps, "notes-saas"), "--format", "json", "--all");
    expect(() => JSON.parse(c.out.join("\n"))).not.toThrow();
    expect(c.err.join("\n")).toContain("Seaworthy Agency");
  });
});

describe("login, logout and status", () => {
  it("login activates this machine, status shows the tier, logout frees the slot", async () => {
    const c = cli();
    expect(await c.run("login", PRO_KEY, "--label", "test laptop")).toBe(0);
    expect(c.all()).toContain("Logged in: Seaworthy Pro on test laptop");
    expect(c.all()).not.toContain(PRO_KEY); // never print the full key
    const saved = JSON.parse(readFileSync(join(work, "config", "licence.json"), "utf8"));
    expect(saved).toMatchObject({ key: PRO_KEY, tier: "pro", machineLabel: "test laptop" });
    expect(provider.calls[0]).toEqual({ op: "activate", key: PRO_KEY, label: "test laptop" });

    const s = cli();
    await s.run("status");
    expect(s.all()).toMatch(/Seaworthy Pro\s+·\s+active/);
    expect(s.all()).toContain("test laptop");

    const o = cli();
    await o.run("logout");
    expect(o.all()).toContain("Logged out");
    expect(existsSync(join(work, "config", "licence.json"))).toBe(false);
    expect(provider.keys.get(PRO_KEY)!.activations.size).toBe(0);
  });

  it("explains failures in plain English", async () => {
    const c = cli();
    expect(await c.run("login", "SEAWORTHY-NOPE-0000")).toBe(1);
    expect(c.all()).toContain("wasn't recognised");
    for (let i = 0; i < 2; i++) await provider.activate(PRO_KEY, `other${i}`);
    const d = cli();
    expect(await d.run("login", PRO_KEY)).toBe(1);
    expect(d.all()).toContain("as many machines as your plan allows");
  });

  it("status on Free shows the plans", async () => {
    const c = cli();
    await c.run("status");
    expect(c.all()).toContain("Seaworthy Free");
    expect(c.all()).toContain("£12/month or £99/year");
    expect(c.all()).toContain("£349/year");
  });
});

describe("Pro", () => {
  async function asPro(key = PRO_KEY) {
    await cli().run("login", key);
  }

  it("--format html writes a self-contained, masked report with the disclaimer", async () => {
    await asPro();
    const apps = copyApps();
    const c = cli();
    expect(await c.run(join(apps, "notes-saas"), "--format", "html")).toBe(1);
    const html = readFileSync(join(work, "seaworthy-report.html"), "utf8");
    expect(html).toContain(DISCLAIMER);
    expect(html).toContain(`Seaworthy found ${findingCount(join(apps, "notes-saas"))} problems in notes-saas`);
    expect(html).toMatch(/<span class="brand-name">Seaworthy<\/span>/);
    // No external resources of any kind. CSS can only load url() from style blocks and
    // attributes; code excerpts may legitimately say `new URL(…)` as escaped text.
    expect(html).not.toMatch(/<script|<link|src="http|href="http/i);
    const css = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>|style="([^"]*)"/gi)].map((m) => m[1] ?? m[2]).join("\n");
    expect(css).not.toMatch(/url\(/i);
    expect(html).toContain("Content-Security-Policy");
    // Every secret from the fixture is masked.
    const env = readFileSync(join(apps, "notes-saas", ".env"), "utf8");
    const secrets = [
      ...[...env.matchAll(/^(?:\w*SERVICE_ROLE_KEY|STRIPE_WEBHOOK_SECRET)=(\S+)$/gm)].map((m) => m[1]!),
      env.match(/postgres:\/\/postgres:([^@]+)@/)![1]!, // the database password itself
    ];
    expect(secrets).toHaveLength(4);
    const stripe = readFileSync(join(apps, "notes-saas", "lib", "stripe.ts"), "utf8").match(/sk_live_\w+/)![0];
    for (const s of [...secrets, stripe]) expect(html).not.toContain(s);
  });

  it("records metadata-only history, git-ignored, and shows what changed", async () => {
    await asPro();
    const apps = copyApps();
    const app = join(apps, "notes-saas");
    const before = findingCount(app);
    await cli().run(app);
    // Fix one finding: turn on RLS for payments.
    writeFileSync(join(app, "supabase", "migrations", "0002_rls.sql"), "alter table public.payments enable row level security;\n");
    clock = new Date("2026-11-11T09:00:00Z");
    const second = cli();
    await second.run(app);
    expect(second.all()).toContain(`Since scan #1 (2026-11-10): 1 fixed, 0 new, ${before - 1} still open`);

    const raw = readFileSync(join(app, ".seaworthy", "history.json"), "utf8");
    const history = JSON.parse(raw);
    expect(history.scans).toHaveLength(2);
    for (const f of history.scans.flatMap((s: { findings: object[] }) => s.findings)) {
      expect(Object.keys(f).sort()).toEqual(["file", "line", "rule", "severity"]);
    }
    expect(raw).not.toMatch(/sk_live|eyJ|whsec_|postgres:\/\//); // no secrets, no code
    expect(readFileSync(join(app, ".seaworthy", ".gitignore"), "utf8")).toContain("*");

    const h = cli();
    expect(await h.run("history", app)).toBe(0);
    expect(h.all()).toMatch(/#1.*\n.*#2/);
    expect(h.all()).toContain(`${before} → ${before - 1} findings, down 1`);

    const cmp = cli();
    expect(await cmp.run("compare", app)).toBe(0);
    expect(cmp.all()).toContain("✔ 1 fixed");
    expect(cmp.all()).toMatch(/Fixed\s+critical\s+SW-D01\s+supabase\/migrations\/0001_init\.sql:20/);
  });

  it("--no-history records nothing", async () => {
    await asPro();
    const apps = copyApps();
    await cli().run(join(apps, "chat-agent"), "--no-history");
    expect(existsSync(join(apps, "chat-agent", ".seaworthy"))).toBe(false);
  });

  it("Pro with agency branding configured: report is produced with Seaworthy branding, one upsell line", async () => {
    await asPro();
    const apps = copyApps();
    const app = join(apps, "notes-saas");
    writeFileSync(join(app, "seaworthy.config.json"), JSON.stringify({ report: { agencyName: "Acme Studio", clientName: "Bob's Bakery" } }));
    const c = cli();
    await c.run(app, "--format", "html");
    const html = readFileSync(join(work, "seaworthy-report.html"), "utf8");
    expect(html).not.toContain("Acme Studio");
    expect(c.all()).toContain("Seaworthy Agency (£349/year) unlocks white-label reports");
  });
});

describe("Agency", () => {
  it("white-label: agency name, client name and logo, no Seaworthy branding, disclaimer kept", async () => {
    await cli().run("login", AGENCY_KEY);
    const apps = copyApps();
    const app = join(apps, "notes-saas");
    writeFileSync(join(app, "logo.svg"), '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(1)</script></svg>');
    writeFileSync(join(app, "seaworthy.config.json"), JSON.stringify({ report: { agencyName: "Acme <Studio>", clientName: "Bob's Bakery", logo: "logo.svg" } }));
    await cli().run(app, "--format", "html", "--output", "client.html");
    const html = readFileSync(join(work, "client.html"), "utf8");
    expect(html).toContain("Acme &lt;Studio&gt;");
    expect(html).toContain("Prepared for <strong>Bob&#39;s Bakery</strong>");
    expect(html).toMatch(/<img class="logo" src="data:image\/svg\+xml;base64,/);
    expect(html).not.toContain("<script"); // the SVG is base64 inside an <img>, never inline
    expect(html).not.toMatch(/Generated by Seaworthy|class="brand-name">Seaworthy/);
    expect(html).toContain(DISCLAIMER);
  });

  it("--all scans every project with its own config and writes one combined report", async () => {
    await cli().run("login", AGENCY_KEY);
    const apps = copyApps();
    // Branding lives in the top folder's config, as an agency would set it up.
    writeFileSync(join(apps, "seaworthy.config.json"), JSON.stringify({ report: { agencyName: "Northlight Studio" } }));
    // chat-agent turns every rule off in its own config; notes-saas keeps defaults.
    const allOff = Object.fromEntries(RULES.map((r) => [r.id, "off"]));
    writeFileSync(join(apps, "chat-agent", "seaworthy.config.json"), JSON.stringify({ rules: allOff }));
    mkdirSync(join(apps, "empty-folder"));
    const c = cli();
    expect(await c.run(apps, "--all", "--format", "html")).toBe(1);
    expect(c.all()).toContain("✖ 1 of 2 projects not seaworthy: notes-saas");
    const html = readFileSync(join(work, "seaworthy-report.html"), "utf8");
    expect(html).toContain("Security scan: 2 projects");
    expect(html).toContain('id="p-notes-saas"');
    expect(html).toContain('id="p-chat-agent"');
    expect(html).toContain("Seaworthy found no problems in chat-agent");
    expect(html).toContain("Northlight Studio");
  });
});

describe("hygiene", () => {
  it("a stray real network call fails the test suite", async () => {
    await expect(fetch("https://example.com")).rejects.toThrow(/Network call attempted/);
  });
  it("PURCHASE_URL is defined once", () => {
    const src = readFileSync(resolve(__dirname, "../src/licensing/config.ts"), "utf8");
    expect(src).toContain("export const PURCHASE_URL");
  });
});
