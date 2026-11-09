import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { RULES } from "../src/rules/index.js";

const FIXTURES = resolve(__dirname, "../fixtures/apps");
const ids = (r: ReturnType<typeof scan>) => r.findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`).sort();

/** Builds a throwaway project, so no key-shaped strings are committed for these tests. */
function project(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), "seaworthy-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), c);
  }
  return { root, done: () => rmSync(root, { recursive: true, force: true }) };
}
const rand = (n: number) => randomBytes(n * 2).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, n);
const jwt = (payload: object) =>
  [{ alg: "HS256", typ: "JWT" }, payload].map((o) => Buffer.from(JSON.stringify(o)).toString("base64url")).join(".") + "." + rand(43);

describe("notes-saas fixture", () => {
  const r = scan(join(FIXTURES, "notes-saas"), DEFAULT_CONFIG, RULES);

  it("finds exactly the planted SW-S01 and SW-D01 flaws", () => {
    expect(ids(r).filter((s) => /SW-(S01|D01)/.test(s))).toEqual([
      "SW-D01 supabase/migrations/0001_init.sql:20",
      "SW-S01 .env:3",
      "SW-S01 .env:4",
      "SW-S01 .env:5",
      "SW-S01 .env:6",
      "SW-S01 lib/stripe.ts:3",
    ]);
  });
  it("does not flag the public anon key (decoy)", () => {
    expect(r.findings.some((f) => f.file === ".env" && f.line === 2)).toBe(false);
  });
  it("detects the stack", () => {
    expect(r.stack.sort()).toEqual(["nextjs", "react", "stripe", "supabase"]);
  });
  it("fails the build", () => expect(r.failed).toBe(true));
});

describe("chat-agent fixture", () => {
  const r = scan(join(FIXTURES, "chat-agent"), DEFAULT_CONFIG, RULES);
  it("finds the plain-text GitHub token and DB password in the MCP config", () => {
    expect(ids(r).filter((s) => s.startsWith("SW-S01"))).toEqual([
      "SW-S01 .cursor/mcp.json:11",
      "SW-S01 .cursor/mcp.json:5",
    ]);
  });
  it("does not flag the Firebase web config key (decoy)", () => {
    expect(r.findings.some((f) => f.file === "lib/firebase.ts")).toBe(false);
  });
});

describe("SW-S01 committed secrets", () => {
  it("vulnerable: flags real-looking keys", () => {
    const p = project({
      "a.ts": `const k = "sk_live_51${rand(60)}";\nconst g = "ghp_${rand(36)}";`,
      "b.env": `SUPABASE_KEY=${jwt({ role: "service_role", iss: "supabase" })}`,
    });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(ids(r)).toEqual(["SW-S01 a.ts:1", "SW-S01 a.ts:2", "SW-S01 b.env:1"]);
    expect(r.findings.find((f) => f.file === "b.env")?.title).toBe("Supabase service-role key committed");
  });
  it("fixed: env vars, placeholders, anon keys and local DB URLs are fine", () => {
    const p = project({
      "a.ts": `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);`,
      ".env.example": `STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx\nGITHUB=ghp_${"0".repeat(36)}`,
      "c.ts": `const anon = "${jwt({ role: "anon", iss: "supabase" })}";`,
      "docker.env": `DATABASE_URL=postgres://postgres:${rand(16)}@localhost:5432/app`,
    });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.findings).toEqual([]);
  });
  it("respects .gitignore: an ignored .env is not committed, so not a finding", () => {
    const p = project({ ".gitignore": ".env\n", ".env": `K=sk_live_51${rand(60)}` });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.findings).toEqual([]);
  });
  it("honours seaworthy-ignore only with a reason", () => {
    const key = `sk_live_51${rand(60)}`;
    const p = project({
      "a.ts": `// seaworthy-ignore SW-S01 revoked test key, kept for docs\nconst a = "${key}";\n// seaworthy-ignore SW-S01\nconst b = "${key}";`,
    });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(ids(r)).toEqual(["SW-S01 a.ts:4"]);
    expect(r.suppressed).toHaveLength(1);
    expect(r.missingReason).toHaveLength(1);
  });
});

describe("SW-D01 table without RLS", () => {
  const supa = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...supa, ...files });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    return ids(r);
  };

  it("vulnerable: flags a public table with no RLS", () => {
    expect(run({ "supabase/migrations/1_init.sql": "-- init\ncreate table posts (id int);" })).toEqual([
      "SW-D01 supabase/migrations/1_init.sql:2",
    ]);
  });
  it("fixed: RLS enabled in a later migration counts", () => {
    expect(
      run({
        "supabase/migrations/1_init.sql": "create table public.posts (id int);",
        "supabase/migrations/2_rls.sql": "ALTER TABLE ONLY \"public\".\"posts\" ENABLE ROW LEVEL SECURITY;",
      }),
    ).toEqual([]);
  });
  it("fixed: RLS enabled inside a DO block counts", () => {
    expect(
      run({
        "supabase/migrations/1.sql": "create table posts (id int);\ndo $$ begin\n  alter table posts enable row level security;\nend $$;",
      }),
    ).toEqual([]);
  });
  it("ignores private schemas, temp tables, dropped tables and API-revoked tables", () => {
    expect(
      run({
        "supabase/migrations/1.sql": [
          "create table private.secrets (id int);",
          "create temp table scratch (id int);",
          "create table old (id int); drop table old;",
          "create table internal (id int); revoke all on table internal from anon, authenticated;",
        ].join("\n"),
      }),
    ).toEqual([]);
  });
  it("is not fooled by SQL inside strings, comments or function bodies", () => {
    expect(
      run({
        "supabase/migrations/1.sql": [
          "create table t (id int);",
          "-- alter table t enable row level security;",
          "select 'alter table t enable row level security;';",
          "create function f() returns void as $fn$ alter table t enable row level security; $fn$ language sql;",
        ].join("\n"),
      }),
    ).toEqual(["SW-D01 supabase/migrations/1.sql:1"]);
  });
  it("re-flags a table whose RLS was disabled later", () => {
    expect(
      run({
        "supabase/migrations/1.sql": "create table t (id int); alter table t enable row level security;",
        "supabase/migrations/2.sql": "alter table t disable row level security;",
      }),
    ).toEqual(["SW-D01 supabase/migrations/1.sql:1"]);
  });
  it("does not run on projects without Supabase", () => {
    const p = project({ "supabase-free/migrations/1.sql": "create table t (id int);" });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.rulesRun).not.toContain("SW-D01");
  });
});
