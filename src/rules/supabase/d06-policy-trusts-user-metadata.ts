import type { RawFinding, Rule } from "../types.js";
import { EXPOSED_SCHEMAS, replayMigrations, type Policy, type PolicyClause } from "./migrations.js";

interface Token {
  kind: "str" | "id" | "num" | "op";
  /** Strings without quotes; identifiers lower-cased unless they were quoted. */
  value: string;
}

/** Splits a policy expression (comments already removed) into strings, identifiers and operators. */
function tokenize(expr: string): Token[] {
  const out: Token[] = [];
  const re = /'((?:[^']|'')*)'|"((?:[^"]|"")*)"|([A-Za-z_][A-Za-z0-9_$]*)|(\d+(?:\.\d+)?)|(->>|->|#>>|#>|::)|(\S)/g;
  for (const m of expr.matchAll(re)) {
    if (m[1] !== undefined) out.push({ kind: "str", value: m[1].replace(/''/g, "'") });
    else if (m[2] !== undefined) out.push({ kind: "id", value: m[2].replace(/""/g, '"') });
    else if (m[3] !== undefined) out.push({ kind: "id", value: m[3].toLowerCase() });
    else if (m[4] !== undefined) out.push({ kind: "num", value: m[4] });
    else out.push({ kind: "op", value: (m[5] ?? m[6])! });
  }
  return out;
}

const is = (t: Token | undefined, kind: Token["kind"], value?: string) =>
  !!t && t.kind === kind && (value === undefined || t.value === value);

/** Index of the `(` matching the `)` at `close`, or -1. */
function openParen(toks: Token[], close: number): number {
  let depth = 0;
  for (let i = close; i >= 0; i--) {
    if (is(toks[i], "op", ")")) depth++;
    else if (is(toks[i], "op", "(") && --depth === 0) return i;
  }
  return -1;
}

/** Index of the `)` matching the `(` at `open`, or -1. */
function closeParen(toks: Token[], open: number): number {
  let depth = 0;
  for (let i = open; i < toks.length; i++) {
    if (is(toks[i], "op", "(")) depth++;
    else if (is(toks[i], "op", ")") && --depth === 0) return i;
  }
  return -1;
}

/** Start of a dotted name (`auth.jwt`) whose last part is at `end`. */
function nameStart(toks: Token[], end: number): number {
  let i = end;
  while (is(toks[i - 1], "op", ".") && is(toks[i - 2], "id")) i -= 2;
  return i;
}

/** Start of the operand that ends just before `end` (exclusive), skipping casts such as `::jsonb` or `::text[]`. */
function leftOperand(toks: Token[], end: number): number {
  let j = end - 1;
  for (;;) {
    if (is(toks[j], "op", "]") && is(toks[j - 1], "op", "[")) j -= 2;
    else if (is(toks[j], "id") && is(toks[j - 1], "op", "::")) j -= 2;
    else break;
  }
  if (is(toks[j], "op", ")")) {
    const open = openParen(toks, j);
    if (open < 0) return -1;
    return is(toks[open - 1], "id") ? nameStart(toks, open - 1) : open;
  }
  return is(toks[j], "id") ? nameStart(toks, j) : -1;
}

type Source = "jwt" | "claims";

/**
 * Whether the tokens are the caller's JWT: `auth.jwt()`, `(select auth.jwt())` (as the
 * performance advice and `supabase db dump` write it), or `current_setting('request.jwt.claims', …)`,
 * with any casts and parentheses around them.
 */
function jwtSource(slice: Token[]): Source | null {
  let t = slice;
  for (let prev = -1; prev !== t.length; ) {
    prev = t.length;
    if (is(t[0], "op", "(") && closeParen(t, 0) === t.length - 1) t = t.slice(1, -1);
    if (is(t[0], "id", "select")) t = t.slice(1);
    if (is(t.at(-1), "id") && is(t.at(-2), "op", "::")) t = t.slice(0, -2);
    if (is(t.at(-1), "id") && is(t.at(-2), "id", "as")) t = t.slice(0, -2);
  }
  const text = t.map((x) => (x.kind === "str" ? `'${x.value}'` : x.value)).join("");
  if (text === "auth.jwt()") return "jwt";
  if (/^current_setting\('request\.jwt\.claims'(?:::text)?(?:,.*)?\)$/.test(text)) return "claims";
  return null;
}

const EXTRACT_PATH = new Set(["jsonb_extract_path", "jsonb_extract_path_text", "json_extract_path", "json_extract_path_text"]);

/** First element of a JSON path written as `'{a,b}'` or `array['a', 'b']`, starting at `i`. */
function pathHead(toks: Token[], i: number): string | undefined {
  const t = toks[i];
  if (is(t, "str")) return /^\{\s*"?([^,"}]*)"?/.exec(t!.value)?.[1]?.trim();
  if (is(t, "id", "array") && is(toks[i + 1], "op", "[") && is(toks[i + 2], "str")) return toks[i + 2]!.value;
  return undefined;
}

/** What the expression reads from user metadata, in words for the message, or null if it doesn't. */
export function userMetadataRead(expr: string): string | null {
  const toks = tokenize(expr);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.kind === "op" && ["->", "->>", "#>", "#>>"].includes(t.value)) {
      const key = t.value.startsWith("#") ? pathHead(toks, i + 1) : is(toks[i + 1], "str") ? toks[i + 1]!.value : undefined;
      if (key !== "user_metadata") continue;
      const start = leftOperand(toks, i);
      const src = start < 0 ? null : jwtSource(toks.slice(start, i));
      if (src === "jwt") return "`auth.jwt() -> 'user_metadata'`";
      if (src === "claims") return "`user_metadata` from `current_setting('request.jwt.claims')`";
    }
    if (t.kind === "id" && EXTRACT_PATH.has(t.value) && is(toks[i + 1], "op", "(")) {
      const close = closeParen(toks, i + 1);
      const args: Token[][] = [[]];
      let depth = 0;
      for (let k = i + 2; k < close; k++) {
        const a = toks[k]!;
        if (is(a, "op", "(")) depth++;
        if (is(a, "op", ")")) depth--;
        if (depth === 0 && is(a, "op", ",")) args.push([]);
        else args.at(-1)!.push(a);
      }
      if (args.length >= 2 && is(args[1]![0], "str", "user_metadata") && jwtSource(args[0]!)) {
        return `\`user_metadata\` from the JWT (\`${t.value}\`)`;
      }
    }
    // Older PostgREST versions set one setting per claim.
    if (is(t, "id", "current_setting") && is(toks[i + 1], "op", "(") && is(toks[i + 2], "str", "request.jwt.claim.user_metadata")) {
      return "`current_setting('request.jwt.claim.user_metadata')`";
    }
  }
  // raw_user_meta_data is the column auth.users keeps user_metadata in.
  const fromAuthUsers = toks.some(
    (t, i) =>
      (is(t, "id", "from") || is(t, "id", "join")) &&
      is(toks[i + 1], "id", "auth") &&
      is(toks[i + 2], "op", ".") &&
      is(toks[i + 3], "id", "users"),
  );
  if (fromAuthUsers && toks.some((t) => is(t, "id", "raw_user_meta_data"))) return "`raw_user_meta_data` from `auth.users`";
  return null;
}

/** Whether the Data API's users (anon or signed in) are among the roles the policy applies to. */
function apiRoles(policy: Policy): boolean {
  return policy.roles.some((r) => r === "public" || r === "anon" || r === "authenticated");
}

export const d06PolicyTrustsUserMetadata: Rule = {
  id: "SW-D06",
  title: "Row-level security policy trusts user-editable metadata",
  severity: "high",
  confidence: "high",
  appliesTo: ["supabase"],
  docs: {
    summary:
      "Every signed-in user can change their own `user_metadata` from the browser with " +
      "`supabase.auth.updateUser({ data: { ... } })`, and Supabase copies it into their JWT. A policy that " +
      "reads a role, an admin flag, a plan or a team ID from `auth.jwt() -> 'user_metadata'` (or from " +
      "`raw_user_meta_data` in `auth.users`) can be passed by anyone who signs up and sets that value on " +
      "themselves. Read the role from `app_metadata`, which only server code with the service role can set, " +
      "or from a roles table that users can't write to.",
    bad:
      `alter table public.invoices enable row level security;\n` +
      `create policy "admins read all" on public.invoices\n` +
      `  for select using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');`,
    good:
      `alter table public.invoices enable row level security;\n` +
      `create policy "admins read all" on public.invoices\n` +
      `  for select using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');`,
  },

  check({ project }) {
    const { tables } = replayMigrations(project);
    const out: RawFinding[] = [];
    for (const t of tables.values()) {
      // A table without RLS is SW-D01's finding; its policies don't apply until RLS is on.
      if (!t.rlsEnabled || t.temporary || t.apiRevoked || !EXPOSED_SCHEMAS.has(t.schema)) continue;
      for (const p of t.policies.values()) {
        // Restrictive policies count too: the caller can set whatever value they check.
        if (!apiRoles(p)) continue;
        let hit: { clause: PolicyClause; what: string; word: string } | null = null;
        for (const [clause, word] of [
          [p.using, "using"],
          [p.check, "with check"],
        ] as const) {
          const what = clause ? userMetadataRead(clause.expr) : null;
          if (clause && what) {
            hit = { clause, what, word };
            break;
          }
        }
        if (!hit) continue;
        const qualified = `${t.schema}.${t.name}`;
        const name = `"${p.name}"`;
        const { clause, what, word } = hit;
        const where = `${clause.file}:${project.position(clause.file, clause.offset).line}`;
        out.push({
          title: `Policy ${name} on ${qualified} trusts user_metadata, which users can edit`,
          file: p.file,
          ...project.position(p.file, p.offset),
          why:
            `Policy ${name} on ${qualified} has \`${word} (${short(clause.expr)})\`, which reads ${what}` +
            (what.includes("raw_user_meta_data") ? `. That column holds each user's user_metadata. ` : `. `) +
            `Any signed-in user can change their own user_metadata from the browser with \`supabase.auth.updateUser\`, ` +
            `so they can give themselves whatever value this policy checks (such as an admin role) and pass it.` +
            (clause.altered ? ` That expression was set by an \`alter policy\` at ${where}.` : ``),
          fix:
            `Read the role from \`auth.jwt() -> 'app_metadata'\`, which only server code with the service role can set, ` +
            `or from a roles table joined on \`auth.uid()\` that users can't write to. Make sure no client code writes the role.`,
          fixPrompt:
            `In my Supabase migrations, the row-level security policy ${name} on ${qualified} (created in ${p.file}` +
            (clause.altered ? `, changed at ${where}` : ``) +
            `) reads ${what.replace(/`/g, "")}, which every user can edit for themselves with supabase.auth.updateUser, ` +
            `so anyone can pass it. Write a new migration that drops and recreates this policy to read the role from ` +
            `auth.jwt() -> 'app_metadata' (set only from server code with the service role) or from a roles table joined ` +
            `on auth.uid() that users can't write to. Then check that no client code writes the role. Don't edit existing migrations.`,
        });
      }
    }
    return out;
  },
};

function short(expr: string): string {
  return expr.length > 60 ? `${expr.slice(0, 57)}...` : expr;
}
