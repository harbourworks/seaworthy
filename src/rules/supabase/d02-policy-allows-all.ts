import type { Confidence } from "../../core/finding.js";
import type { RawFinding, Rule } from "../types.js";
import { EXPOSED_SCHEMAS, replayMigrations, type Policy, type PolicyClause, type TableState } from "./migrations.js";

/** What a policy expression lets through. */
type Openness = "everyone" | "signed-in";

/**
 * Classifies a USING or WITH CHECK expression. Only expressions that are plainly always
 * true, or that only check someone is logged in, count. Anything that looks at the row
 * (an owner column, a team membership, a status) is left alone: that is a real policy.
 */
export function classifyExpr(expr: string): Openness | null {
  let e = expr.toLowerCase().replace(/\s+/g, "");
  // Supabase's performance advice wraps auth calls in a subquery: (select auth.uid()).
  e = e.replace(/\(select(auth\.(?:uid|role|jwt)\(\))\)/g, "$1");
  while (/^\(.*\)$/.test(e) && balanced(e.slice(1, -1))) e = e.slice(1, -1);
  if (/^(true|1=1|'t'|'true'|true::bool(ean)?|'true'::bool(ean)?)$/.test(e)) return "everyone";
  if (
    /^(auth\.uid\(\)isnotnull|auth\.role\(\)='authenticated'|'authenticated'=auth\.role\(\)|auth\.jwt\(\)isnotnull)$/.test(e)
  ) {
    return "signed-in";
  }
  return null;
}

function balanced(s: string): boolean {
  let d = 0;
  for (const ch of s) {
    if (ch === "(") d++;
    else if (ch === ")" && --d < 0) return false;
  }
  return d === 0;
}

/** Who a policy applies to, given its roles and how open its expression is. */
function audience(policy: Policy, openness: Openness): Openness | null {
  const roles = new Set(policy.roles);
  const anon = roles.has("public") || roles.has("anon");
  if (!anon && !roles.has("authenticated")) return null; // service_role or a custom role: not the Data API's users
  return anon && openness === "everyone" ? "everyone" : "signed-in";
}

const WHO: Record<Openness, string> = {
  everyone: "anyone with your public anon key",
  "signed-in": "any signed-in user",
};
const WHO_SHORT: Record<Openness, string> = { everyone: "anyone", "signed-in": "any signed-in user" };

/** What a trivially-true USING clause allows, by command. */
const USING_ALLOWS: Record<Policy["command"], string> = {
  select: "read every row",
  update: "change every row",
  delete: "delete every row",
  all: "read, change and delete every row",
  insert: "add rows", // INSERT policies have no USING clause; kept for completeness
};

export const d02PolicyAllowsAll: Rule = {
  id: "SW-D02",
  title: "Row-level security policy that allows everyone",
  severity: "high",
  confidence: "high",
  appliesTo: ["supabase"],
  docs: {
    summary:
      "Turning on row-level security only helps if the policies actually restrict rows. A policy " +
      "with `using (true)` or `with check (true)` lets every caller through, so the table is as " +
      "open as if RLS were off. Checking only that someone is logged in (`auth.uid() is not null`) " +
      "is nearly as open, because anyone can sign up. Policies should compare the row with the " +
      "caller, usually `auth.uid() = user_id`. A table that is genuinely public, such as a product " +
      "list, can keep a `using (true)` read policy: mark it with a `seaworthy-ignore` comment saying so.",
    bad:
      `alter table public.notes enable row level security;\n` +
      `create policy "Notes are readable" on public.notes\n` +
      `  for select using (true);`,
    good:
      `alter table public.notes enable row level security;\n` +
      `create policy "Users read own notes" on public.notes\n` +
      `  for select to authenticated using ((select auth.uid()) = user_id);`,
  },

  check({ project }) {
    const { tables } = replayMigrations(project);
    const out: RawFinding[] = [];
    for (const t of tables.values()) {
      // A table without RLS is SW-D01's finding; its policies don't apply until RLS is on.
      if (!t.rlsEnabled || t.temporary || t.apiRevoked || !EXPOSED_SCHEMAS.has(t.schema)) continue;
      for (const p of t.policies.values()) {
        if (!p.permissive) continue; // a restrictive policy can only narrow access
        const draft = findingFor(t, p);
        if (!draft) continue;
        const { clause, ...rest } = draft;
        out.push({ ...rest, file: clause.file, ...project.position(clause.file, clause.offset) });
      }
    }
    return out;
  },
};

interface Draft extends Omit<RawFinding, "file" | "line" | "column"> {
  clause: PolicyClause;
}

function findingFor(t: TableState, p: Policy): Draft | null {
  const qualified = `${t.schema}.${t.name}`;
  const owned = t.ownerColumns.length > 0;
  const owner = t.ownerColumns[0] ?? "user_id";
  const name = `"${p.name}"`;
  const scoped = `(select auth.uid()) = ${owner}`;

  // USING decides which existing rows a caller can see, change or delete.
  const usingOpen = p.using && p.command !== "insert" ? classifyExpr(p.using.expr) : null;
  const usingWho = usingOpen ? audience(p, usingOpen) : null;
  if (p.using && usingWho) {
    const reads = p.command === "select";
    // Logged-in users reading a table with no owner column is usually shared data, by design.
    if (reads && !owned && usingWho === "signed-in") return null;
    const confidence: Confidence = reads && !owned ? "medium" : "high";
    const allows = USING_ALLOWS[p.command];
    return {
      clause: p.using,
      confidence,
      title: `Policy on ${qualified} lets ${WHO_SHORT[usingWho]} ${allows}`,
      why:
        `Policy ${name} on ${qualified} has \`using (${short(p.using.expr)})\`, so ${WHO[usingWho]} can ${allows}` +
        (owned ? `, including other users' rows.` : `.`) +
        (usingWho === "signed-in" ? ` Anyone can sign up, so that is close to everyone.` : ``) +
        (reads && !owned ? ` If this table is meant to be public, such as a product list, that may be fine.` : ``),
      fix: owned
        ? `Limit the policy to the row's owner: \`using (${scoped})\`` +
          (p.command === "select" ? `.` : `, and add \`with check (${scoped})\` so nobody can hand a row to someone else.`)
        : reads
          ? `If the table is public by design, add \`-- seaworthy-ignore SW-D02 <reason>\` on the line before \`using\`. ` +
            `Otherwise add an owner column (\`${owner} uuid references auth.users\`) and use \`using (${scoped})\`.`
          : `Only let callers change rows they own: add an owner column (\`${owner} uuid references auth.users\`) ` +
            `and use \`using (${scoped})\`, or restrict the policy to \`service_role\`.`,
      fixPrompt:
        `In my Supabase migrations, the policy ${name} on ${qualified} has \`using (${short(p.using.expr)})\`, which lets ` +
        `${WHO[usingWho]} ${allows}. Write a new migration that drops and recreates this policy so each user ` +
        `can only ${p.command === "select" ? "read" : "access"} their own rows` +
        (owned ? `, using \`${scoped}\`` : `; add an owner column referencing auth.users if the table needs one`) +
        `. Don't edit existing migrations.`,
    };
  }

  // WITH CHECK decides what a caller may write. For UPDATE and ALL it defaults to USING, so
  // an explicit open check only matters when it is there.
  const writes = p.command === "insert" || p.command === "update" || p.command === "all";
  const checkOpen = writes && p.check ? classifyExpr(p.check.expr) : null;
  const checkWho = checkOpen ? audience(p, checkOpen) : null;
  if (p.check && checkWho) {
    const inserting = p.command === "insert";
    const allows = inserting
      ? owned
        ? "add rows on behalf of any user"
        : "add any rows they like"
      : owned
        ? "rewrite rows they can edit, including handing them to another user"
        : "write any values into rows they can edit";
    return {
      clause: p.check,
      // An open insert into a table with no owner (a waitlist, a contact form) is often deliberate.
      confidence: owned ? "high" : "medium",
      title: `Policy on ${qualified} lets ${WHO_SHORT[checkWho]} ${allows}`,
      why:
        `Policy ${name} on ${qualified} has \`with check (${short(p.check.expr)})\`, so ${WHO[checkWho]} can ${allows}.` +
        (owned ? ` Nothing checks that ${owner} is the caller's own ID.` : ` Nothing limits what goes in.`),
      fix: owned
        ? `Check the owner on write: \`with check (${scoped})\`.`
        : `If open writes are intended (a waitlist or contact form), add \`-- seaworthy-ignore SW-D02 <reason>\` on the line before \`with check\`, and ` +
          `add rate limiting. Otherwise restrict the check, or the roles the policy applies to.`,
      fixPrompt:
        `In my Supabase migrations, the policy ${name} on ${qualified} has \`with check (${short(p.check.expr)})\`, ` +
        `which lets ${WHO[checkWho]} ${allows}. Write a new migration that drops and recreates the policy with a ` +
        `check that only allows the caller to write their own rows` +
        (owned ? ` (\`${scoped}\`)` : ``) +
        `. Don't edit existing migrations.`,
    };
  }
  return null;
}

function short(expr: string): string {
  return expr.length > 60 ? `${expr.slice(0, 57)}...` : expr;
}
