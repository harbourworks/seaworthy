import { describe, expect, it, beforeEach, afterEach, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createServer as netServer, type Server, type Socket } from "node:net";
import { createServer as tlsServer, TLSSocket } from "node:tls";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";
import { PURCHASE_URL } from "../src/licensing/config.js";
import { decide, slackPayload, alertMessage, type AlertInput } from "../src/pro/alerts.js";
import { formatMessage, sendMail, SmtpError } from "../src/pro/smtp.js";
import { SCHEDULE_WORKFLOW } from "../src/cli/init.js";
import type { Finding } from "../src/core/finding.js";

const NOTES_SAAS = resolve(__dirname, "../fixtures/apps/notes-saas");
const PRO_KEY = "SEAWORTHY-TEST-PRO-0001";
const SLACK = "https://hooks.slack.com/services/T000/B000/test";
const HOOK = "https://alerts.example.com/seaworthy";
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

let work: string;
let app: string;
let provider: MockProvider;
let posts: Array<{ url: string; body: any }>;
let slackStatus: number;

/** Answers OSV with no advisories, records Slack and webhook posts, and fails anything else. */
const fakeFetch = (async (url: string, init?: RequestInit) => {
  if (url.endsWith("/querybatch")) {
    const { queries } = JSON.parse(String(init!.body)) as { queries: unknown[] };
    return new Response(JSON.stringify({ results: queries.map(() => ({})) }));
  }
  if (url === SLACK || url === HOOK) {
    posts.push({ url, body: JSON.parse(String(init!.body)) });
    return new Response("ok", { status: url === SLACK ? slackStatus : 200 });
  }
  throw new Error(`unexpected fetch ${url}`);
}) as unknown as typeof fetch;

function cli(env: NodeJS.ProcessEnv = {}) {
  const out: string[] = [];
  const deps: CliDeps = {
    out: (s) => out.push(strip(s)),
    err: (s) => out.push(strip(s)),
    env: { SEAWORTHY_CONFIG_DIR: join(work, "config"), ...env },
    cwd: work,
    now: () => new Date("2026-11-10T09:00:00Z"),
    provider,
    fetch: fakeFetch,
  };
  return { out, all: () => out.join("\n"), run: (...argv: string[]) => run(argv, deps) };
}
const pro = (extra: NodeJS.ProcessEnv = {}) =>
  cli({ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SLACK_WEBHOOK: SLACK, SEAWORTHY_WEBHOOK_URL: HOOK, ...extra });

beforeEach(() => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-alerts-"));
  app = join(work, "app");
  cpSync(NOTES_SAAS, app, { recursive: true });
  provider = new MockProvider().addKey(PRO_KEY, "pro");
  posts = [];
  slackStatus = 200;
});
afterEach(() => rmSync(work, { recursive: true, force: true }));

describe("scan --notify (Pro)", () => {
  it("alerts on the first scan, stays quiet when nothing changes, then alerts only on what's new", async () => {
    const env = { GITHUB_REPOSITORY: "acme/notes", GITHUB_SERVER_URL: "https://github.com", GITHUB_RUN_ID: "123" };
    expect(await pro(env).run(app, "--notify")).toBe(1);
    expect(posts.map((p) => p.url)).toEqual([SLACK, HOOK]);
    const first = posts.find((p) => p.url === HOOK)!.body;
    expect(first.reason).toBe("new");
    expect(first.repository).toBe("acme/notes");
    expect(first.runUrl).toBe("https://github.com/acme/notes/actions/runs/123");
    expect(first.findings.length).toBeGreaterThan(5);

    posts = [];
    const quiet = pro(env);
    expect(await quiet.run(app, "--notify")).toBe(1); // still failing: same exit code
    expect(posts).toEqual([]);
    expect(quiet.all()).toContain("No new problems since the last scan, so no alert was sent.");

    mkdirSync(join(app, "app/api/search2"));
    cpSync(join(app, "app/api/search/route.ts"), join(app, "app/api/search2/route.ts"));
    posts = [];
    const c = pro(env);
    await c.run(app, "--notify");
    const hook = posts.find((p) => p.url === HOOK)!.body;
    expect(hook.findings.map((f: any) => `${f.rule} ${f.file}`)).toEqual(["SW-A05 app/api/search2/route.ts"]);
    expect(hook.title).toBe("Seaworthy: 1 new problem in acme/notes (1 high)");
    const slack = posts.find((p) => p.url === SLACK)!.body;
    expect(slack.text).toBe(hook.title);
    expect(JSON.stringify(slack.blocks)).toContain("app/api/search2/route.ts:13");
    expect(c.all()).toContain("Alert sent to Slack.");
    expect(c.all()).toContain("Alert sent to the webhook.");
  });

  it("--notify-on failing alerts on every failing scan; always alerts even when clean", async () => {
    await pro().run(app, "--notify");
    posts = [];
    await pro().run(app, "--notify", "--notify-on", "failing");
    expect(posts.find((p) => p.url === HOOK)!.body.reason).toBe("failing");

    const clean = join(work, "clean");
    mkdirSync(clean);
    writeFileSync(join(clean, "index.js"), "console.log(1);\n");
    posts = [];
    expect(await pro().run(clean, "--notify", "--notify-on", "always")).toBe(0);
    expect(posts.find((p) => p.url === HOOK)!.body.title).toBe("Seaworthy: no problems at or above high in clean");
  });

  it("never sends code or secret values", async () => {
    await pro().run(app, "--notify");
    const sent = JSON.stringify(posts);
    const env = readFileSync(join(app, ".env"), "utf8");
    for (const m of env.matchAll(/=(\S{20,})$/gm)) expect(sent).not.toContain(m[1]!);
    expect(sent).not.toMatch(/create table|stripe\.webhooks|process\.env/);
  });

  it("a failed delivery makes the run exit 2 and says why", async () => {
    slackStatus = 500;
    const c = pro();
    expect(await c.run(app, "--notify")).toBe(2);
    expect(c.all()).toContain("Slack refused the alert (HTTP 500).");
    expect(c.all()).toContain("Alert sent to the webhook.");
  });

  it("checks the set-up before scanning: no destination, a non-https URL, --offline, --all", async () => {
    for (const [env, args, msg] of [
      [{ SEAWORTHY_LICENCE: PRO_KEY }, [], /nowhere to send/],
      [{ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SLACK_WEBHOOK: "http://hooks.slack.com/x" }, [], /must be an https/],
      [{ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SLACK_WEBHOOK: SLACK }, ["--offline"], /can't be combined with --offline/],
      [{ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SLACK_WEBHOOK: SLACK }, ["--all"], /can't be combined with --all/],
      [{ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SLACK_WEBHOOK: SLACK }, ["--notify-on", "sometimes"], /new, failing or always/],
      [{ SEAWORTHY_LICENCE: PRO_KEY, SEAWORTHY_SMTP_URL: "smtps://me@example.com:pw@smtp.example.com" }, [], /SEAWORTHY_EMAIL_TO/],
    ] as const) {
      const c = cli(env as NodeJS.ProcessEnv);
      expect(await c.run(app, "--notify", ...args)).toBe(2);
      expect(c.all()).toMatch(msg);
    }
    expect(posts).toEqual([]);
  });

  it("without Pro: a normal scan, no alert sent, one upsell line", async () => {
    const c = cli({ SEAWORTHY_SLACK_WEBHOOK: SLACK });
    expect(await c.run(app, "--notify")).toBe(1);
    expect(posts).toEqual([]);
    const upsells = c.all().split("\n").filter((l) => l.includes(PURCHASE_URL));
    expect(upsells).toHaveLength(1);
    expect(upsells[0]).toMatch(/Scanned without sending an alert\. Seaworthy Pro .* unlocks scheduled scans with Slack and email alerts/);
  });
});

describe("alert content", () => {
  const f = (over: Partial<Finding>): Finding =>
    ({ ruleId: "SW-D01", title: "Table t has no RLS", severity: "critical", confidence: "high", file: "a.sql", line: 1, column: 1, why: "", fix: "", ...over }) as Finding;
  const input = (over: Partial<AlertInput> = {}): AlertInput => ({ project: "p", version: "t", failOn: "high", findings: [], added: null, fixedCount: 0, ...over });

  it("only counts findings at or above failOn as worth an alert", () => {
    const low = f({ severity: "low", ruleId: "SW-B01" });
    expect(decide(input({ findings: [low], added: [low] }), "new").send).toBe(false);
    expect(decide(input({ findings: [low], added: [low] }), "always")).toMatchObject({ send: true, kind: "clean" });
  });

  it("escapes Slack markup, so names from code can't mention people or add links", () => {
    const evil = f({ title: "Table <!channel> <https://evil.example|click> & co has no RLS" });
    const m = alertMessage(input({ findings: [evil], added: [evil] }), decide(input({ findings: [evil], added: [evil] }), "new"));
    const s = JSON.stringify(slackPayload(m));
    expect(s).not.toContain("<!channel>");
    expect(s).not.toContain("<https://evil");
    expect(s).toContain("&lt;!channel&gt;");
  });
});

describe("email over SMTP", () => {
  let key = "";
  let cert = "";
  let openssl = true;
  beforeAll(() => {
    const dir = mkdtempSync(join(tmpdir(), "seaworthy-tls-"));
    try {
      execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], { stdio: "ignore" });
      key = readFileSync(join(dir, "k.pem"), "utf8");
      cert = readFileSync(join(dir, "c.pem"), "utf8");
    } catch {
      openssl = false;
    }
    rmSync(dir, { recursive: true, force: true });
  });

  /** A tiny SMTP server that records what it's sent. starttls: offer STARTTLS on a plain socket; implicit: TLS from the start. */
  function fakeSmtp(mode: "starttls" | "implicit" | "plain-only") {
    const got = { auth: "", from: "", to: [] as string[], data: "", tls: false };
    const handle = (raw: Socket) => {
      let sock: Socket = raw;
      let buf = "";
      let inData = false;
      const send = (s: string) => sock.write(s + "\r\n");
      const onLine = (line: string) => {
        if (inData) {
          if (line === ".") {
            inData = false;
            send("250 queued");
          } else got.data += line + "\n";
          return;
        }
        const cmd = line.toUpperCase();
        if (cmd.startsWith("EHLO")) send(mode === "starttls" && !got.tls ? "250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN" : "250-localhost\r\n250 AUTH PLAIN LOGIN");
        else if (cmd === "STARTTLS") {
          send("220 go ahead");
          sock.removeAllListeners("data");
          const t = new TLSSocket(sock, { isServer: true, key, cert });
          got.tls = true;
          sock = t;
          t.on("data", onData);
        } else if (cmd.startsWith("AUTH PLAIN")) {
          got.auth = Buffer.from(line.slice(11), "base64").toString();
          send("235 ok");
        } else if (cmd.startsWith("MAIL FROM")) (got.from = line, send("250 ok"));
        else if (cmd.startsWith("RCPT TO")) (got.to.push(line), send("250 ok"));
        else if (cmd === "DATA") (inData = true, send("354 go"));
        else if (cmd === "QUIT") (send("221 bye"), sock.end());
        else send("500 what");
      };
      const onData = (d: Buffer) => {
        buf += d.toString();
        let nl;
        while ((nl = buf.indexOf("\r\n")) >= 0) {
          const l = buf.slice(0, nl);
          buf = buf.slice(nl + 2);
          onLine(l);
        }
      };
      sock.on("data", onData);
      sock.on("error", () => {});
      send("220 localhost ESMTP");
    };
    const server: Server = mode === "implicit" ? tlsServer({ key, cert }, (s) => ((got.tls = true), handle(s))) : netServer(handle);
    return new Promise<{ port: number; got: typeof got; close: () => void }>((ok) =>
      server.listen(0, "127.0.0.1", () => ok({ port: (server.address() as { port: number }).port, got, close: () => server.close() })),
    );
  }

  const msg = { from: "alerts@example.com", to: ["dev@example.com", "ops@example.com"], subject: "Seaworthy: 1 new problem in acme/notes (1 critical)", text: "CRITICAL  Table x  a.sql:1  SW-D01\n" };

  it.skipIf(!openssl)("STARTTLS: upgrades before logging in, and delivers the message", async () => {
    if (!openssl) return;
    const s = await fakeSmtp("starttls");
    try {
      await sendMail({ secure: false, host: "localhost", port: s.port, user: "alerts@example.com", pass: "p@ss" }, msg, { tls: { ca: cert } });
      expect(s.got.tls).toBe(true);
      expect(s.got.auth).toBe("\0alerts@example.com\0p@ss");
      expect(s.got.to).toEqual(["RCPT TO:<dev@example.com>", "RCPT TO:<ops@example.com>"]);
      const [headers, body] = s.got.data.split("\n\n");
      expect(headers).toContain("Subject: Seaworthy: 1 new problem in acme/notes (1 critical)");
      expect(Buffer.from(body!.replace(/\s/g, ""), "base64").toString()).toContain("CRITICAL  Table x  a.sql:1  SW-D01");
    } finally {
      s.close();
    }
  });

  it.skipIf(!openssl)("implicit TLS (smtps://) works too", async () => {
    if (!openssl) return;
    const s = await fakeSmtp("implicit");
    try {
      await sendMail({ secure: true, host: "localhost", port: s.port, user: "u@example.com", pass: "p" }, msg, { tls: { ca: cert } });
      expect(s.got.tls).toBe(true);
      expect(s.got.data).toContain("Content-Transfer-Encoding: base64");
    } finally {
      s.close();
    }
  });

  it.skipIf(!openssl)("refuses to send a password when the server offers no STARTTLS, and rejects untrusted certificates", async () => {
    if (!openssl) return;
    const plain = await fakeSmtp("plain-only");
    try {
      await expect(sendMail({ secure: false, host: "localhost", port: plain.port, user: "u@example.com", pass: "p" }, msg)).rejects.toThrow(/won't send your password unencrypted/);
      expect(plain.got.auth).toBe("");
    } finally {
      plain.close();
    }
    const s = await fakeSmtp("implicit");
    try {
      await expect(sendMail({ secure: true, host: "localhost", port: s.port, user: "u@example.com", pass: "p" }, msg, { timeoutMs: 5000 })).rejects.toBeInstanceOf(SmtpError);
    } finally {
      s.close();
    }
  });

  it("strips line breaks from headers, so nothing can be injected", () => {
    const m = formatMessage({ ...msg, subject: "Hi\r\nBcc: victim@example.com" }, new Date("2026-11-10T09:00:00Z"));
    expect(m).not.toMatch(/\r\nBcc:/);
    expect(m).toContain("Subject: Hi Bcc: victim@example.com");
    expect(m.endsWith("\r\n.\r\n")).toBe(true);
  });
});

describe("init --schedule", () => {
  it("writes a weekly workflow that keeps history in the cache and passes secrets as env", async () => {
    const dir = join(work, "fresh");
    mkdirSync(dir);
    const c = cli();
    expect(await c.run("init", dir, "--schedule")).toBe(0);
    const wf = readFileSync(join(dir, ".github", "workflows", "seaworthy-scheduled.yml"), "utf8");
    expect(wf).toBe(SCHEDULE_WORKFLOW);
    expect(existsSync(join(dir, ".github", "workflows", "seaworthy.yml"))).toBe(false);
    expect(wf).toMatch(/cron: "17 7 \* \* 1"/);
    expect(wf).toContain("workflow_dispatch");
    expect(wf).toContain("actions/cache/restore@v6");
    expect(wf).toContain("actions/cache/save@v6");
    expect(wf).toContain("npx --yes seaworthy-cli@0 --notify");
    expect(wf).toContain("SEAWORTHY_SLACK_WEBHOOK: ${{ secrets.SEAWORTHY_SLACK_WEBHOOK }}");
    expect(wf).not.toMatch(/run: .*\$\{\{/); // no expressions pasted into shell commands
    expect(c.all()).toContain("SEAWORTHY_LICENCE");
  });
});
