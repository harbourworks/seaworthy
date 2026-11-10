import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";
import { PORTAL_URL, PURCHASE_URL } from "../src/licensing/config.js";
import { openUrl } from "../src/cli/open.js";

const PRO_KEY = "SEAWORTHY-TEST-PRO-0001";
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

let work: string;
let provider: MockProvider;

function cli(opts: { interactive?: boolean; env?: NodeJS.ProcessEnv } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const opened: string[] = [];
  const deps: CliDeps = {
    out: (s) => out.push(strip(s)),
    err: (s) => err.push(strip(s)),
    env: { SEAWORTHY_CONFIG_DIR: join(work, "config"), ...opts.env },
    cwd: work,
    now: () => new Date("2026-11-10T09:00:00Z"),
    provider,
    interactive: opts.interactive ?? false,
    openUrl: (u) => (opened.push(u), true),
  };
  return { out, err, opened, all: () => [...out, ...err].join("\n"), run: (...argv: string[]) => run(argv, deps) };
}

beforeEach(() => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-buy-"));
  provider = new MockProvider().addKey(PRO_KEY, "pro");
});
afterEach(() => rmSync(work, { recursive: true, force: true }));

describe("seaworthy buy", () => {
  it("shows the plans, the checkout link and what to do after paying", async () => {
    const c = cli();
    expect(await c.run("buy")).toBe(0);
    const t = c.all();
    expect(t).toMatch(/Free\s+£0/);
    expect(t).toMatch(/Pro\s+£12\/month or £99\/year\s+\+ pull-request checks, HTML reports, history, compare, scheduled alerts · 2 machines/);
    expect(t).toMatch(/Agency\s+£349\/year\s+\+ white-label reports, --all · 10 machines/);
    expect(t).toContain(`Buy: ${PURCHASE_URL}`);
    expect(t).toContain(`Get your key: ${PORTAL_URL}`);
    expect(t).toContain("seaworthy login <key>");
    expect(t).toContain("SEAWORTHY_LICENCE");
    expect(provider.calls).toEqual([]); // no licence calls, no network
  });

  it("opens the checkout for a person at a terminal, but never in CI, when piped or with --no-open", async () => {
    const person = cli({ interactive: true });
    await person.run("buy");
    expect(person.opened).toEqual([PURCHASE_URL]);
    expect(person.all()).toContain("Opened the checkout in your browser");

    const ci = cli({ interactive: false });
    await ci.run("buy");
    expect(ci.opened).toEqual([]);

    const optedOut = cli({ interactive: true });
    await optedOut.run("buy", "--no-open");
    expect(optedOut.opened).toEqual([]);
  });

  it("upgrade is the same command, and it says when you already have a plan", async () => {
    await cli().run("login", PRO_KEY);
    const c = cli();
    expect(await c.run("upgrade")).toBe(0);
    expect(c.all()).toMatch(/You're logged in on this machine with Seaworthy Pro/);
    expect(c.all()).toContain(PURCHASE_URL);
  });
});

describe("finding your key", () => {
  it("login with no key says exactly where the key is, and opens the portal at a terminal", async () => {
    const c = cli({ interactive: true });
    expect(await c.run("login")).toBe(2);
    expect(c.all()).toContain(`Your key is in the customer portal: ${PORTAL_URL}`);
    expect(c.all()).toMatch(/Enter the email you bought with/);
    expect(c.all()).toContain("No plan yet? seaworthy buy");
    expect(c.opened).toEqual([PORTAL_URL]);

    const ci = cli();
    await ci.run("login");
    expect(ci.opened).toEqual([]);
  });

  it("error messages link straight to the portal, not to an email", async () => {
    const wrong = cli();
    expect(await wrong.run("login", "NOT-A-REAL-KEY")).toBe(1);
    expect(wrong.all()).toContain(PORTAL_URL);
    expect(wrong.all()).not.toMatch(/purchase email/);
  });

  it("status on Free points to seaworthy buy and login", async () => {
    const c = cli();
    await c.run("status");
    expect(c.all()).toContain("seaworthy buy to open the checkout, then seaworthy login <key>");
  });

  it("help lists buy and where to find the key", async () => {
    const c = cli();
    await c.run("--help");
    expect(c.all()).toMatch(/seaworthy buy\s+See the plans and open the checkout/);
    expect(c.all()).toContain(`find your key: ${PORTAL_URL}`);
  });
});

describe("opening links", () => {
  it("only opens plain https links, so a link can't become a command", () => {
    for (const bad of ["http://example.com/x", "https://example.com/x\" & calc", "file:///etc/passwd", "https://a.com/$(id)", "javascript:alert(1)"]) {
      expect(openUrl(bad, "linux")).toBe(false);
    }
  });
  it("both links pass that check", () => {
    const re = /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_\-./?=&%~]*$/;
    expect(PURCHASE_URL).toMatch(re);
    expect(PORTAL_URL).toMatch(re);
  });
});
