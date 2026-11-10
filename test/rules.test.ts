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

  it("finds exactly the planted SW-S01, SW-D01 and SW-D02 flaws", () => {
    expect(ids(r).filter((s) => /SW-(S01|D01|D02)/.test(s))).toEqual([
      "SW-D01 supabase/migrations/0001_init.sql:20",
      "SW-D02 supabase/migrations/0001_init.sql:18",
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

describe("SW-D02 policy that allows everyone", () => {
  const supa = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }) };
  /** Every SW-D02 finding at any confidence, as "line confidence". */
  const run = (sql: string | Record<string, string>) => {
    const files = typeof sql === "string" ? { "supabase/migrations/1.sql": sql } : sql;
    const p = project({ ...supa, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    const shown = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    const d02 = (r: ReturnType<typeof scan>) => r.findings.filter((f) => f.ruleId === "SW-D02");
    return {
      all: d02(all).map((f) => `${f.line} ${f.confidence}`),
      shown: d02(shown).map((f) => `${f.line} ${f.confidence}`),
      titles: d02(all).map((f) => f.title),
      suppressed: all.suppressed.filter((f) => f.ruleId === "SW-D02").length,
    };
  };
  const owned =
    "create table notes (id uuid primary key, user_id uuid references auth.users, body text);\n" +
    "alter table notes enable row level security;\n";
  const unowned =
    "create table products (id int primary key, name text);\n" + "alter table products enable row level security;\n";

  it("vulnerable: anyone can read every row of a table that belongs to users", () => {
    const r = run(owned + "create policy read_all on notes\n  for select using (true);");
    expect(r.all).toEqual(["4 high"]);
    expect(r.titles[0]).toBe("Policy on public.notes lets anyone read every row");
  });
  it("fixed: a policy scoped to the owner is not flagged, with or without the subquery wrapper", () => {
    expect(run(owned + "create policy own on notes for select using (auth.uid() = user_id);").all).toEqual([]);
    expect(run(owned + "create policy own on notes for select using ((select auth.uid()) = user_id);").all).toEqual([]);
  });
  it("a public read on a table with no owner column is medium confidence, hidden by default", () => {
    const r = run(unowned + "create policy catalogue on products for select using (true);");
    expect(r.all).toEqual(["3 medium"]);
    expect(r.shown).toEqual([]);
  });
  it("checking only that someone is logged in counts as open, on owned tables", () => {
    expect(run(owned + "create policy p on notes for select using (auth.uid() is not null);").titles).toEqual([
      "Policy on public.notes lets any signed-in user read every row",
    ]);
    expect(run(owned + "create policy p on notes for select to authenticated using (true);").all).toEqual(["3 high"]);
    // Logged-in users reading shared, unowned data is normal.
    expect(run(unowned + "create policy p on products for select to authenticated using (true);").all).toEqual([]);
  });
  it("ignores restrictive policies and policies for service_role or custom roles", () => {
    expect(run(owned + "create policy p on notes as restrictive for select using (true);").all).toEqual([]);
    expect(run(owned + "create policy p on notes for all to service_role using (true);").all).toEqual([]);
    expect(run(owned + 'create policy p on notes for select to "Reporting Role" using (true);').all).toEqual([]);
  });
  it("vulnerable: open writes", () => {
    expect(run(owned + "create policy p on notes for update using (true);").titles).toEqual([
      "Policy on public.notes lets anyone change every row",
    ]);
    expect(run(unowned + "create policy p on products for delete using (true);").all).toEqual(["3 high"]);
    expect(run(owned + "create policy p on notes for insert\n  with check (true);").all).toEqual(["4 high"]);
    // An open insert with no owner column (a waitlist) is often deliberate.
    expect(run(unowned + "create policy p on products for insert with check (true);").all).toEqual(["3 medium"]);
  });
  it("vulnerable: an update scoped by USING but open in WITH CHECK lets rows be handed to anyone", () => {
    const r = run(owned + "create policy p on notes for update\n  using (auth.uid() = user_id)\n  with check (true);");
    expect(r.all).toEqual(["5 high"]);
    expect(r.titles[0]).toContain("handing them to another user");
  });
  it("follows later migrations: dropped and altered policies, renamed tables, added owner columns", () => {
    const open = "create policy p on notes for select using (true);";
    const two = (second: string) => ({ "supabase/migrations/1.sql": owned + open, "supabase/migrations/2.sql": second });
    expect(run(two("drop policy if exists p on notes;")).all).toEqual([]);
    expect(run(two("alter policy p on notes using (auth.uid() = user_id);")).all).toEqual([]);
    expect(run(two("alter table notes rename to memos;")).titles).toEqual([
      "Policy on public.memos lets anyone read every row",
    ]);
    expect(
      run({
        "supabase/migrations/1.sql": unowned + "create policy p on products for select using (true);",
        "supabase/migrations/2.sql": "alter table products add column owner_id uuid;",
      }).all,
    ).toEqual(["3 high"]);
  });
  it("finds owners declared as a table-level foreign key", () => {
    const sql =
      "create table docs (id int, author uuid, foreign key (author) references auth.users (id));\n" +
      "alter table docs enable row level security;\ncreate policy p on docs for select using (true);";
    expect(run(sql).all).toEqual(["3 high"]);
  });
  it("leaves tables without RLS to SW-D01", () => {
    expect(run("create table t (user_id uuid);\ncreate policy p on t for select using (true);").all).toEqual([]);
  });
  it("is not fooled by policy names, comments, strings or subqueries", () => {
    expect(run(owned + 'create policy "using (true)" on notes for select using (auth.uid() = user_id);').all).toEqual([]);
    expect(run(owned + "-- create policy p on notes for select using (true);\nselect 1;").all).toEqual([]);
    expect(run(owned + "create policy p on notes for select using (body = 'true');").all).toEqual([]);
    expect(
      run(owned + "create policy p on notes for select using (exists (select 1 from members m where m.user_id = auth.uid()));")
        .all,
    ).toEqual([]);
    expect(
      run(owned + "create policy p on notes for select using (true /* for now */ and auth.uid() = user_id);").all,
    ).toEqual([]);
  });
  it("points at the expression, also inside DO blocks and across lines", () => {
    expect(run(owned + "do $$ begin\n  create policy p on notes for select using (true);\nend $$;").all).toEqual([
      "4 high",
    ]);
    expect(run(owned + "create policy p on notes for select using (\n\n  true\n);").all).toEqual(["5 high"]);
  });
  it("honours a seaworthy-ignore comment with a reason", () => {
    const r = run(
      unowned + "create policy p on products for select\n  -- seaworthy-ignore SW-D02 public product catalogue\n  using (true);",
    );
    expect(r.all).toEqual([]);
    expect(r.suppressed).toBe(1);
  });
});

describe("SW-D02 on `supabase db dump` output", () => {
  it("reads quoted names, quoted roles and foreign keys added after the table", () => {
    const sql = [
      'CREATE TABLE IF NOT EXISTS "public"."invoices" (',
      '    "id" bigint NOT NULL,',
      '    "customer" "uuid" NOT NULL',
      ");",
      'ALTER TABLE ONLY "public"."invoices"',
      '    ADD CONSTRAINT "invoices_customer_fkey" FOREIGN KEY ("customer") REFERENCES "auth"."users"("id");',
      'CREATE POLICY "Authenticated can read invoices" ON "public"."invoices" FOR SELECT TO "authenticated" USING (true);',
      'ALTER TABLE "public"."invoices" ENABLE ROW LEVEL SECURITY;',
    ].join("\n");
    const p = project({
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }),
      "supabase/migrations/20240101000000_remote_schema.sql": sql,
    });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.findings.map((f) => `${f.ruleId} ${f.line} ${f.confidence} ${f.title}`)).toEqual([
      "SW-D02 7 high Policy on public.invoices lets any signed-in user read every row",
    ]);
  });
});
