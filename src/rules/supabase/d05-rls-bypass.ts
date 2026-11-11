import type { RawFinding, Rule } from "../types.js";
import { EXPOSED_SCHEMAS, replayMigrations, type FunctionState } from "./migrations.js";

/**
 * EXECUTE on a new function is granted to PUBLIC, and Supabase also grants it to anon and
 * authenticated, so only revoking it from all three keeps the API roles out.
 */
function apiCanCall(fn: FunctionState): boolean {
  return !["public", "anon", "authenticated"].every((r) => fn.revoked.has(r));
}

export const d05RlsBypass: Rule = {
  id: "SW-D05",
  title: "View or SECURITY DEFINER function bypasses row-level security",
  severity: "high",
  confidence: "high",
  appliesTo: ["supabase"],
  docs: {
    summary:
      "A Postgres view runs with its owner's rights unless it is created with `security_invoker = true`, " +
      "so row-level security on the tables it reads doesn't apply to callers. A view in the public schema " +
      "is served by the Data API like a table, so anyone with your anon key can read every row through it. " +
      "A `security definer` function also runs as its owner and skips RLS, and anyone with the anon key can " +
      "call it at `/rest/v1/rpc/<name>`. Without `set search_path`, the names it uses are looked up on the " +
      "caller's search path.",
    bad:
      `alter table public.notes enable row level security;\n` +
      `create view public.note_previews as select id, user_id, left(body, 80) from public.notes;`,
    good:
      `alter table public.notes enable row level security;\n` +
      `create view public.note_previews with (security_invoker = true) as\n` +
      `  select id, user_id, left(body, 80) from public.notes;`,
  },

  check({ project }) {
    const { tables, views, functions } = replayMigrations(project);
    const out: RawFinding[] = [];

    for (const v of views.values()) {
      if (v.securityInvoker || v.apiRevoked || !EXPOSED_SCHEMAS.has(v.schema)) continue;
      // Views over tables without RLS are SW-D01's finding: the table itself is already open.
      const guarded = v.sources.map((k) => tables.get(k)).filter((t) => t && t.rlsEnabled);
      if (guarded.length === 0) continue;
      const view = `${v.schema}.${v.name}`;
      const list = guarded.map((t) => `${t!.schema}.${t!.name}`);
      const names = list.length > 1 ? `${list.slice(0, -1).join(", ")} and ${list.at(-1)}` : list[0]!;
      const has = list.length > 1 ? "have" : "has";
      out.push({
        title: `View ${view} bypasses row-level security on ${names}`,
        file: v.file,
        ...project.position(v.file, v.offset),
        why:
          `${view} reads ${names}, which ${has} row-level security, but the view runs with its owner's rights, so ` +
          `those policies don't apply to its callers. Supabase serves the view through the Data API, so anyone ` +
          `with your public anon key can read every row it returns.`,
        fix:
          `Add a migration with \`alter view ${view} set (security_invoker = true);\` (Postgres 15 or later), so ` +
          `queries through the view run as the caller and the RLS policies on ${names} apply.`,
        fixPrompt:
          `In my Supabase migrations, the view ${view} reads ${names}, which ${has} row-level security, but the view ` +
          `doesn't set security_invoker, so it bypasses the RLS policies. Write a new migration that runs ` +
          `\`alter view ${view} set (security_invoker = true);\`, and check that the policies on ${names} still ` +
          `let users read what the view needs. Don't edit existing migrations.`,
      });
    }

    for (const fn of functions.values()) {
      if (!fn.securityDefiner || fn.searchPath || fn.returnsTrigger || !EXPOSED_SCHEMAS.has(fn.schema)) continue;
      if (!apiCanCall(fn)) continue;
      const name = `${fn.schema}.${fn.name}`;
      out.push({
        title: `Function ${name} runs as its owner (security definer) with no search_path`,
        confidence: "medium",
        file: fn.file,
        ...project.position(fn.file, fn.offset),
        why:
          `${name} is \`security definer\`, so it runs with its owner's rights and row-level security doesn't ` +
          `apply inside it. It is in the public schema and EXECUTE isn't revoked, so anyone with your anon key ` +
          `can call it at /rest/v1/rpc/${fn.name}. It also doesn't set search_path, so the tables and functions ` +
          `it names are looked up on the caller's search path.`,
        fix:
          `If it doesn't need to bypass RLS, make it \`security invoker\`. Otherwise add \`set search_path = ''\`, ` +
          `write every table name with its schema (such as \`public.notes\`), and make sure it only touches the caller's ` +
          `own rows. If only your server calls it, add \`revoke execute on function ${name} from public, anon, authenticated;\`.`,
        fixPrompt:
          `In my Supabase migrations, the function ${name} is security definer with no search_path, and the anon ` +
          `and authenticated roles can call it through the API. Write a new migration that recreates it with ` +
          `\`set search_path = ''\` and schema-qualified names, or as security invoker if it doesn't need to bypass ` +
          `row-level security. If only the server calls it, also revoke execute from public, anon and ` +
          `authenticated. Don't edit existing migrations.`,
      });
    }
    return out;
  },
};
