import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { ProjectFiles } from "../src/core/project.js";
import { RULES } from "../src/rules/index.js";
import { formatSql, replayMigrations } from "../src/rules/supabase/migrations.js";

const SUPA = { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }) };

function withProject<T>(files: Record<string, string>, fn: (root: string) => T): T {
  const root = mkdtempSync(join(tmpdir(), "seaworthy-do-"));
  try {
    for (const [p, c] of Object.entries(files)) {
      mkdirSync(dirname(join(root, p)), { recursive: true });
      writeFileSync(join(root, p), c);
    }
    return fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** Replays one migration file and returns its tables, plus a way to turn offsets into lines. */
function replay(sql: string) {
  return withProject({ "supabase/migrations/1.sql": sql }, (root) => {
    const project = new ProjectFiles(root, ["supabase/migrations/1.sql"]);
    const state = replayMigrations(project);
    const line = (offset: number) => project.position("supabase/migrations/1.sql", offset).line;
    return { tables: state.tables, line };
  });
}

/** SW-D01 and SW-D02 findings at any confidence, as "rule file:line confidence | title". */
function dFindings(root: string, minConfidence: "low" | "medium" = "low") {
  const r = scan(root, { ...DEFAULT_CONFIG, minConfidence }, RULES);
  return r.findings
    .filter((f) => f.ruleId === "SW-D01" || f.ruleId === "SW-D02")
    .map((f) => `${f.ruleId} ${f.file}:${f.line} ${f.confidence} | ${f.title}`);
}
const run = (sql: string, minConfidence: "low" | "medium" = "low") =>
  withProject({ ...SUPA, "supabase/migrations/1.sql": sql }, (root) =>
    dFindings(root, minConfidence).map((s) => s.replace(" supabase/migrations/1.sql:", " ")),
  );
const findingsOf = (sql: string) =>
  withProject({ ...SUPA, "supabase/migrations/1.sql": sql }, (root) =>
    scan(root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES).findings.filter((f) => f.ruleId.startsWith("SW-D")),
  );

const TABLES =
  "create table public.orders (id uuid primary key, total numeric);\n" +
  "create table public.notes (id uuid primary key, body text);\n";

describe("formatSql: Postgres format() with one variable for every argument", () => {
  it("substitutes %I, %s and positional %1$I / %1$s", () => {
    expect(formatSql("alter table public.%I enable row level security", 1, "orders")).toBe(
      "alter table public.orders enable row level security",
    );
    expect(formatSql('create policy "w %1$s" on public.%1$I', 1, "notes")).toBe('create policy "w notes" on public.notes');
    expect(formatSql("%s and %s", 2, "x")).toBe("x and x");
    expect(formatSql("100%% of %I", 1, "t")).toBe("100% of t");
  });
  it("quotes %I like quote_ident: mixed case, spaces and quotes", () => {
    expect(formatSql("%I", 1, "TeamMembers")).toBe('"TeamMembers"');
    expect(formatSql("%I", 1, 'my "t"')).toBe('"my ""t"""');
    // quote_ident would also quote keywords such as user; the replay reads both spellings the same.
    expect(formatSql("%I", 1, "user")).toBe("user");
    expect(formatSql("%s", 1, "TeamMembers")).toBe("TeamMembers");
  });
  it("gives up on anything it can't be sure of", () => {
    expect(formatSql("%L", 1, "x")).toBeNull();
    expect(formatSql("%2$I", 1, "x")).toBeNull();
    expect(formatSql("%s %s", 1, "x")).toBeNull();
    expect(formatSql("%-10s", 1, "x")).toBeNull();
    expect(formatSql("%*s", 1, "x")).toBeNull();
    expect(formatSql("trailing %", 1, "x")).toBeNull();
  });
});

describe("replayMigrations: foreach over a literal array with execute format()", () => {
  const repro =
    TABLES +
    "do $$\ndeclare\n  tbl text;\nbegin\n  foreach tbl in array array['orders', 'notes']\n  loop\n" +
    "    execute format('alter table public.%I enable row level security', tbl);\n" +
    "    execute format(\n" +
    "      'create policy \"signed in write %1$s\" on public.%1$I for all to authenticated using (true) with check (true)',\n" +
    "      tbl\n    );\n  end loop;\nend\n$$;\n";

  it("expands every execute for every element, with %1$I, and pins offsets to the execute", () => {
    const { tables, line } = replay(repro);
    for (const name of ["orders", "notes"]) {
      const t = tables.get(`public.${name}`)!;
      expect(t.rlsEnabled, name).toBe(true);
      expect(t.rlsDynamic, name).toBeUndefined();
      const p = t.policies.get(`signed in write ${name}`)!;
      expect(p).toMatchObject({ command: "all", roles: ["authenticated"], permissive: true });
      expect(p.using?.expr).toBe("true");
      expect(p.check?.expr).toBe("true");
      expect(line(p.offset)).toBe(10);
      expect(line(p.using!.offset)).toBe(10);
      expect(line(p.check!.offset)).toBe(10);
      expect(p.file).toBe("supabase/migrations/1.sql");
    }
  });

  it("runs the iterations in order, before the statements after the loop", () => {
    const { tables } = replay(
      TABLES +
        "do $$ declare t text; begin\n" +
        "  foreach t in array array['orders', 'notes'] loop\n" +
        "    execute format('alter table %I enable row level security', t);\n" +
        "    execute format('create policy p on %I using (true)', t);\n" +
        "    execute format('drop policy p on %I', t);\n" +
        "  end loop;\n" +
        "  alter table orders disable row level security;\n" +
        "end $$;",
    );
    expect(tables.get("public.orders")!.rlsEnabled).toBe(false);
    expect(tables.get("public.notes")!.rlsEnabled).toBe(true);
    expect(tables.get("public.notes")!.policies.size).toBe(0);
  });

  it("handles a label, upper case, a ::text[] cast, a quoted element and several statements in one string", () => {
    const { tables } = replay(
      'create table "Teams" (id int);\ncreate table logs (id int);\n' +
        "DO $b$ DECLARE x TEXT; BEGIN <<l>> FOREACH x IN ARRAY ARRAY['Teams', 'it''s']::text[] LOOP\n" +
        "  EXECUTE FORMAT('ALTER TABLE ONLY public.%I ENABLE ROW LEVEL SECURITY', x);\n" +
        "END LOOP l; END $b$;\n" +
        "do $$ declare n text; begin foreach n in array array['logs'] loop\n" +
        "  execute format('alter table %s enable row level security; revoke all on %1$s from anon, authenticated', n);\n" +
        "end loop; end $$;",
    );
    expect(tables.get("public.Teams")!.rlsEnabled).toBe(true);
    expect(tables.get("public.Teams")!.rlsDynamic).toBeUndefined();
    expect(tables.get("public.logs")!.rlsEnabled).toBe(true);
    expect(tables.get("public.logs")!.apiRevoked).toBe(true);
  });

  it("reads a dollar-quoted format string", () => {
    const { tables, line } = replay(
      TABLES +
        "do $$ declare t text; begin foreach t in array array['orders', 'notes'] loop\n" +
        "  execute format('alter table public.%I enable row level security', t);\n" +
        "  execute format($f$\n    create policy \"read %1$s\" on public.%1$I for select using (true)\n  $f$, t);\n" +
        "end loop; end $$;",
    );
    for (const name of ["orders", "notes"]) {
      const p = tables.get(`public.${name}`)!.policies.get(`read ${name}`)!;
      expect(p.using?.expr).toBe("true");
      expect(line(p.using!.offset)).toBe(5);
    }
  });

  it("a loop that doesn't enable RLS leaves the tables without it, and not marked dynamic", () => {
    const { tables } = replay(
      TABLES +
        "do $$ declare t text; begin foreach t in array array['orders', 'notes'] loop\n" +
        "  execute format('create policy \"read %s\" on %I for select using (true)', t, t);\n" +
        "end loop; end $$;",
    );
    for (const t of tables.values()) {
      expect(t.rlsEnabled).toBe(false);
      expect(t.rlsDynamic).toBeUndefined();
      expect(t.policies.size).toBe(1);
    }
  });

  it("ignores 'loop', 'end loop' and execute inside strings and comments", () => {
    const { tables } = replay(
      TABLES +
        "do $$ declare t text; begin\n" +
        "  raise notice 'end loop; execute x';\n" +
        "  -- execute format('alter table %I enable row level security', t);\n" +
        "  foreach t in array array['orders'] loop\n" +
        "    raise notice 'loop end loop';\n" +
        "    execute format('alter table %I enable row level security', t);\n" +
        "  end loop;\n" +
        "end $$;",
    );
    expect(tables.get("public.orders")!.rlsEnabled).toBe(true);
    expect(tables.get("public.notes")!.rlsEnabled).toBe(false);
    expect(tables.get("public.notes")!.rlsDynamic).toBeUndefined();
  });

  it("doesn't mistake grant execute for an execute statement", () => {
    const { tables } = replay(
      TABLES +
        "create function f() returns void language sql as $f$ select 1 $f$;\n" +
        "do $$ begin grant execute on function f() to authenticated; raise notice 'row level security comes next'; end $$;\n",
    );
    expect(tables.get("public.orders")!.rlsDynamic).toBeUndefined();
  });
});

describe("replayMigrations: DO blocks it can't expand mark RLS as possibly dynamic", () => {
  const dynamic = (block: string) => {
    const { tables, line } = replay(TABLES + block + "\ncreate table public.later (id int);");
    const d = (n: string) => {
      const r = tables.get(`public.${n}`)!.rlsDynamic;
      return r ? `${r.file}:${line(r.offset)}` : undefined;
    };
    return { orders: d("orders"), notes: d("notes"), later: d("later"), rls: tables.get("public.orders")!.rlsEnabled };
  };

  it("for ... in select over pg_tables", () => {
    expect(
      dynamic(
        "do $$ declare r record; begin\n" +
          "  for r in select tablename from pg_tables where schemaname = 'public' loop\n" +
          "    execute format('alter table public.%I enable row level security', r.tablename);\n" +
          "  end loop;\nend $$;",
      ),
    ).toEqual({ orders: "supabase/migrations/1.sql:5", notes: "supabase/migrations/1.sql:5", later: undefined, rls: false });
  });
  it("a format string that isn't a literal", () => {
    expect(
      dynamic(
        "do $$ declare t text; s text := 'alter table %I enable row level security'; begin\n" +
          "  foreach t in array array['orders'] loop execute format(s, t); end loop;\nend $$;",
      ).orders,
    ).toBe("supabase/migrations/1.sql:4");
  });
  it("an element that isn't a literal, or an argument other than the loop variable", () => {
    const sql = (arr: string, arg: string) =>
      `do $$ declare t text; begin foreach t in array array[${arr}] loop\n` +
      `  execute format('alter table %I enable row level security', ${arg});\nend loop; end $$;`;
    expect(dynamic(sql("'orders', other_name", "t")).orders).toBeDefined();
    expect(dynamic(sql("'orders'", "upper(t)")).orders).toBeDefined();
    expect(dynamic(sql("'orders'", "t || '_v2'")).orders).toBeDefined();
  });
  it("an array held in a variable", () => {
    expect(
      dynamic(
        "do $$ declare t text; tables text[] := array['orders', 'notes']; begin\n" +
          "  foreach t in array tables loop execute format('alter table public.%I enable row level security', t); end loop;\nend $$;",
      ),
    ).toEqual({ orders: "supabase/migrations/1.sql:4", notes: "supabase/migrations/1.sql:4", later: undefined, rls: false });
  });
  it("string concatenation, execute outside a loop, and an inner loop", () => {
    expect(
      dynamic("do $$ declare t text := 'orders'; begin execute 'alter table ' || quote_ident(t) || ' enable row level security'; end $$;").notes,
    ).toBeDefined();
    expect(
      dynamic(
        "do $$ declare s text; t text; begin foreach s in array array['public'] loop\n" +
          "  foreach t in array array['orders'] loop execute format('alter table %I.%I enable row level security', s, t); end loop;\n" +
          "end loop; end $$;",
      ).orders,
    ).toBeDefined();
  });
  it("only when the block has something to do with row level security", () => {
    expect(
      dynamic(
        "do $$ declare r record; begin for r in select tablename from pg_tables loop\n" +
          "  execute format('grant select on public.%I to authenticated', r.tablename);\nend loop; end $$;",
      ).orders,
    ).toBeUndefined();
  });
  it("a later plain alter table settles it either way", () => {
    const { tables } = replay(
      TABLES +
        "do $$ declare r record; begin for r in select tablename from pg_tables loop\n" +
        "  execute format('alter table %I enable row level security', r.tablename); end loop; end $$;\n" +
        "alter table orders disable row level security;",
    );
    expect(tables.get("public.orders")!.rlsDynamic).toBeUndefined();
    expect(tables.get("public.notes")!.rlsDynamic).toBeDefined();
  });
});

describe("SW-D01 and SW-D02 on DO blocks", () => {
  const RULE_FIXTURES = resolve(__dirname, "../fixtures/rules");
  const file = "supabase/migrations/20260101000000_init.sql";
  const fixture = (rule: string, kind: string) => dFindings(join(RULE_FIXTURES, rule, kind));

  it("sw-d02 vulnerable (the issue's reproduction): no SW-D01, one SW-D02 per table at the execute line", () => {
    expect(fixture("sw-d02", "vulnerable")).toEqual([
      `SW-D02 ${file}:18 high | Policy on public.orders lets any signed-in user read, change and delete every row`,
      `SW-D02 ${file}:18 high | Policy on public.notes lets any signed-in user read, change and delete every row`,
    ]);
    const f = scan(join(RULE_FIXTURES, "sw-d02", "vulnerable"), { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES).findings.filter(
      (x) => x.ruleId === "SW-D02",
    );
    expect(f[0]!.why).toContain('Policy "signed in write orders" on public.orders has `using (true)`');
    expect(f[1]!.why).toContain('Policy "signed in write notes" on public.notes has `using (true)`');
    expect(f[0]!.fixPrompt).toContain('the policy "signed in write orders" on public.orders');
    expect(f[0]!.column).toBe(5);
  });
  it("sw-d02 fixed and decoy: nothing flagged", () => {
    expect(fixture("sw-d02", "fixed")).toEqual([]);
    expect(fixture("sw-d02", "decoy")).toEqual([]);
  });
  it("sw-d01 vulnerable: a loop that never enables RLS is still SW-D01 at high confidence", () => {
    expect(fixture("sw-d01", "vulnerable")).toEqual([
      `SW-D01 ${file}:1 high | Table public.orders has no row-level security`,
      `SW-D01 ${file}:7 high | Table public.notes has no row-level security`,
    ]);
  });
  it("sw-d01 fixed and decoy: nothing flagged", () => {
    expect(fixture("sw-d01", "fixed")).toEqual([]);
    expect(fixture("sw-d01", "decoy")).toEqual([]);
  });

  it("the plain-SQL equivalent gives the same result as before", () => {
    expect(
      run(
        TABLES +
          "alter table public.orders enable row level security;\n" +
          'create policy "signed in write orders" on public.orders for all to authenticated using (true) with check (true);\n',
      ),
    ).toEqual([
      "SW-D01 2 high | Table public.notes has no row-level security",
      "SW-D02 4 high | Policy on public.orders lets any signed-in user read, change and delete every row",
    ]);
  });

  it("computed table names: SW-D01 at low confidence, saying RLS may be enabled dynamically", () => {
    const sql =
      TABLES +
      "do $$ declare r record; begin\n" +
      "  for r in select tablename from pg_tables where schemaname = 'public' loop\n" +
      "    execute format('alter table public.%I enable row level security', r.tablename);\n" +
      "  end loop;\nend $$;";
    expect(run(sql)).toEqual([
      "SW-D01 1 low | Table public.orders may not have row-level security",
      "SW-D01 2 low | Table public.notes may not have row-level security",
    ]);
    expect(run(sql, "medium")).toEqual([]);
    const [f] = findingsOf(sql);
    expect(f!.severity).toBe("critical");
    expect(f!.why).toContain("The `execute` in a DO block at supabase/migrations/1.sql:5 runs SQL that Seaworthy can't work out in advance");
    expect(f!.why).toContain("may enable row-level security on public.orders");
    expect(f!.fix).toContain("alter table public.orders enable row level security;");
    expect(f!.fixPrompt).toContain("public.orders");
  });
});
