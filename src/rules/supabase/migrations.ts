import type { ProjectFiles } from "../../core/project.js";
import {
  IDENT,
  QNAME,
  closingParen,
  dollarBody,
  maskSql,
  normaliseIdent,
  normaliseName,
  splitStatements,
  topLevelCommas,
  type SqlStatement,
} from "./sql.js";

/** Schemas Supabase exposes through its Data API by default. */
export const EXPOSED_SCHEMAS = new Set(["public"]);

export interface TableState {
  schema: string;
  name: string;
  file: string;
  /** Offset of the `create table` statement. */
  offset: number;
  rlsEnabled: boolean;
  /**
   * Set when a DO block ran SQL the replay can't expand (computed table names, a format
   * string that isn't a literal) after the table was created, so RLS may have been enabled
   * there. Points at that block's `execute`. A later plain `alter table` clears it.
   */
  rlsDynamic?: { file: string; offset: number };
  /** API roles had their privileges revoked, so the Data API cannot reach it. */
  apiRevoked: boolean;
  temporary: boolean;
  /** Columns that tie a row to a user: they reference auth.users or have an owner-style name. */
  ownerColumns: string[];
  /** Policies by name, as they stand after every migration. */
  policies: Map<string, Policy>;
}

export type PolicyCommand = "all" | "select" | "insert" | "update" | "delete";

export interface PolicyClause {
  /** The expression inside the parentheses, comments removed, whitespace collapsed. */
  expr: string;
  /** File offset of the expression's first character. */
  offset: number;
  file: string;
}

export interface Policy {
  name: string;
  permissive: boolean;
  command: PolicyCommand;
  /** Lower-cased role names. Postgres defaults to `public` (everyone, including anon). */
  roles: string[];
  using?: PolicyClause;
  check?: PolicyClause;
  file: string;
  offset: number;
}

export interface ViewState {
  schema: string;
  name: string;
  file: string;
  /** Offset of the latest `create [or replace] view` statement. */
  offset: number;
  /** `security_invoker` is on, so the caller's RLS applies to the tables it reads. */
  securityInvoker: boolean;
  /** Keys (`schema.name`) of the relations named after FROM or JOIN in its query. */
  sources: string[];
  /** API roles had their privileges revoked, so the Data API cannot reach it. */
  apiRevoked: boolean;
}

export interface FunctionState {
  schema: string;
  name: string;
  file: string;
  /** Offset of the latest `create [or replace] function` statement. */
  offset: number;
  securityDefiner: boolean;
  /** The function pins its own `search_path` (`set search_path = …`). */
  searchPath: boolean;
  returnsTrigger: boolean;
  /** Roles whose EXECUTE privilege was revoked (and not granted back). */
  revoked: Set<string>;
}

export interface MigrationState {
  tables: Map<string, TableState>;
  views: Map<string, ViewState>;
  functions: Map<string, FunctionState>;
  files: string[];
}

const MIGRATION_FILE_RE = /(^|\/)supabase\/(migrations\/[^/]+\.sql|schema\.sql|seed\.sql)$/i;

export function migrationFiles(project: ProjectFiles): string[] {
  // Supabase applies migrations in filename order (they start with a timestamp).
  return project.files.filter((f) => MIGRATION_FILE_RE.test(f) && !/seed\.sql$/i.test(f)).sort();
}

const CREATE_TABLE = new RegExp(
  String.raw`^create\s+(?:(?:global|local)\s+)?(temp|temporary|unlogged)?\s*table\s+(?:if\s+not\s+exists\s+)?(${QNAME})`,
  "i",
);
const ALTER_RLS = new RegExp(
  String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+(enable|disable)\s+row\s+level\s+security`,
  "i",
);
const RENAME = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+rename\s+to\s+(${QNAME})`, "i");
const SET_SCHEMA = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(${QNAME})\s+set\s+schema\s+(${QNAME})`, "i");
const DROP = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?((?:${QNAME}\s*,\s*)*${QNAME})`, "i");
const CREATE_POLICY = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+(?:table\s+)?(${QNAME})`, "i");
const ALTER_POLICY = new RegExp(
  String.raw`^alter\s+policy\s+(${IDENT})\s+on\s+(${QNAME})(?:\s+rename\s+to\s+(${IDENT}))?`,
  "i",
);
const DROP_POLICY = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+(${QNAME})`, "i");
const ADD_COLUMN = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+add\s`, "i");
const OWNER_NAME =
  /^(user_id|owner_id|author_id|creator_id|created_by|profile_id|account_id|member_id|customer_id|owner|uid)$/;
const REFERENCES_AUTH_USERS = /\breferences\s+(?:auth|"auth")\s*\.\s*(?:users\b|"users")/i;
const BLOCK_BEGIN = /^begin\s+(?!transaction|work)/i;

/** The statement's masked raw text from its first token, with a DO block's `begin` skipped. */
function fromFirstToken(stmt: SqlStatement, masked: string): number {
  let start = stmt.offset - stmt.rawOffset;
  const b = BLOCK_BEGIN.exec(masked.slice(start));
  if (b) start += b[0].length;
  return start;
}

/**
 * Reads the clauses of a CREATE or ALTER POLICY statement. Works on the masked raw text so
 * a policy name, string or comment that happens to contain "using (" can't be mistaken for
 * a clause, and offsets point at the real source.
 */
function policyParts(stmt: SqlStatement, file: string, pin?: number) {
  const masked = maskSql(stmt.raw, true);
  const commentless = maskSql(stmt.raw, false);
  const start = fromFirstToken(stmt, masked);
  const clauses: { using?: PolicyClause; check?: PolicyClause } = {};
  let headerEnd = masked.length;
  const re = /\b(using|with\s+check)\s*\(/gi;
  re.lastIndex = start;
  for (let m = re.exec(masked); m; m = re.exec(masked)) {
    const open = m.index + m[0].length - 1;
    const close = closingParen(masked, open);
    if (close < 0) break;
    // Only clauses at the top level of the statement, not `using` inside a subquery.
    const before = masked.slice(start, m.index);
    if ((before.match(/\(/g)?.length ?? 0) !== (before.match(/\)/g)?.length ?? 0)) continue;
    headerEnd = Math.min(headerEnd, m.index);
    const inner = commentless.slice(open + 1, close);
    const lead = inner.length - inner.trimStart().length;
    const clause = { expr: inner.replace(/\s+/g, " ").trim(), offset: pin ?? stmt.rawOffset + open + 1 + lead, file };
    if (/^using/i.test(m[1]!)) clauses.using = clause;
    else clauses.check = clause;
    re.lastIndex = close + 1;
  }
  const header = masked.slice(start, headerEnd).replace(/\s+/g, " ");
  const as = /\bas\s+(permissive|restrictive)\b/i.exec(header)?.[1]?.toLowerCase();
  const command = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(header)?.[1]?.toLowerCase() as
    | PolicyCommand
    | undefined;
  // Find TO in the masked text, then read the role names from the unmasked text, because
  // `supabase db dump` quotes them: TO "authenticated".
  const to = /\bto\s+/i.exec(masked.slice(start, headerEnd));
  const roles = to
    ? commentless
        .slice(start + to.index + to[0].length, headerEnd)
        .split(",")
        .map((r) => normaliseIdent(r))
        .filter((r) => r.length > 0)
    : undefined;
  return { ...clauses, permissive: as !== "restrictive", command, roles };
}

/** Columns in a CREATE TABLE column list that tie a row to a user. */
function ownerColumnsOf(stmt: SqlStatement): string[] {
  const masked = maskSql(stmt.raw, true);
  const commentless = maskSql(stmt.raw, false);
  const start = fromFirstToken(stmt, masked);
  const head = CREATE_TABLE.exec(masked.slice(start));
  if (!head) return [];
  let open = start + head[0].length;
  while (/\s/.test(masked[open] ?? "")) open++;
  if (masked[open] !== "(") return []; // e.g. CREATE TABLE … AS SELECT
  const close = closingParen(masked, open);
  if (close < 0) return [];
  const out: string[] = [];
  for (const [a, b] of topLevelCommas(masked, open + 1, close)) {
    const el = commentless.slice(a, b).trim();
    const fk = /^(?:constraint\s+\S+\s+)?foreign\s+key\s*\(([^)]*)\)/i.exec(el);
    if (fk) {
      if (REFERENCES_AUTH_USERS.test(el)) out.push(...fk[1]!.split(",").map(normaliseIdent));
      continue;
    }
    if (/^(constraint|primary|unique|check|exclude|like)\b/i.test(el)) continue;
    const col = new RegExp(`^${IDENT}`).exec(el)?.[0];
    if (!col) continue;
    const name = normaliseIdent(col);
    if (REFERENCES_AUTH_USERS.test(el) || OWNER_NAME.test(name)) out.push(name);
  }
  return [...new Set(out)];
}

const REVOKE = new RegExp(String.raw`^revoke\s+.+?\s+on\s+(?:table\s+)?((?:${QNAME}\s*,\s*)*${QNAME})\s+from\s+(.+)$`, "i");

const CREATE_VIEW = new RegExp(
  String.raw`^create\s+(?:or\s+replace\s+)?(temp\s+|temporary\s+)?(?:recursive\s+)?view\s+(${QNAME})`,
  "i",
);
const ALTER_VIEW = new RegExp(
  String.raw`^alter\s+view\s+(?:if\s+exists\s+)?(${QNAME})\s+(set\s*\(|reset\s*\(|rename\s+to\s+(${QNAME})|set\s+schema\s+(${IDENT}))`,
  "i",
);
const DROP_VIEW = new RegExp(String.raw`^drop\s+view\s+(?:if\s+exists\s+)?((?:${QNAME}\s*,\s*)*${QNAME})`, "i");
const CREATE_FUNCTION = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+(${QNAME})`, "i");
const ALTER_FUNCTION = new RegExp(String.raw`^alter\s+function\s+(${QNAME})`, "i");
const DROP_FUNCTION = /^drop\s+function\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$/i;
const FUNCTION_PRIVILEGE =
  /^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(?:(?:function|routine)\s+(.+?)|all\s+(?:functions|routines)\s+in\s+schema\s+(.+?))\s+(?:to|from)\s+(.+)$/i;
const DEFAULT_PRIVILEGE =
  /^alter\s+default\s+privileges\s+(?:for\s+(?:role|user)\s+.+?\s+)?(?:in\s+schema\s+(.+?)\s+)?(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(?:functions|routines)\s+(?:to|from)\s+(.+)$/i;

/** `security_invoker` in a view's option list: true or false if it is there, undefined if not. */
function invokerOption(options: string): boolean | undefined {
  const m = /\bsecurity_invoker\b"?\s*(?:=\s*['"]?([A-Za-z0-9_]+))?/i.exec(options);
  if (!m) return undefined;
  return !m[1] || /^(true|on|yes|1)$/i.test(m[1]);
}

/** Keys of the relations named after FROM or JOIN, including comma lists (`from a x, b y`). */
function relationsRead(masked: string, commentless: string, from: number): string[] {
  const out = new Set<string>();
  const kw = /\b(?:from|join)\s+(?:only\s+)?/gi;
  const rel = new RegExp(String.raw`(${QNAME})(?:\s+(?:as\s+)?${IDENT})?\s*(,\s*)?`, "y");
  kw.lastIndex = from;
  for (let m = kw.exec(masked); m; m = kw.exec(masked)) {
    rel.lastIndex = m.index + m[0].length;
    for (let r = rel.exec(commentless); r; r = rel.exec(commentless)) {
      out.add(normaliseName(r[1]!).key);
      if (!r[2]) break;
    }
  }
  return [...out];
}

/** Reads a CREATE VIEW: its `security_invoker` option and the relations its query reads. */
function viewParts(stmt: SqlStatement): { securityInvoker: boolean; sources: string[] } {
  const masked = maskSql(stmt.raw, true);
  const commentless = maskSql(stmt.raw, false);
  const start = fromFirstToken(stmt, masked);
  const head = CREATE_VIEW.exec(masked.slice(start));
  if (!head) return { securityInvoker: false, sources: [] };
  let i = start + head[0].length;
  const skip = () => {
    while (/\s/.test(masked[i] ?? "")) i++;
  };
  skip();
  if (masked[i] === "(") {
    const close = closingParen(masked, i); // column names
    if (close < 0) return { securityInvoker: false, sources: [] };
    i = close + 1;
    skip();
  }
  let securityInvoker = false;
  const w = /^with\s*\(/i.exec(masked.slice(i));
  if (w) {
    const open = i + w[0].length - 1;
    const close = closingParen(masked, open);
    if (close < 0) return { securityInvoker: false, sources: [] };
    securityInvoker = invokerOption(commentless.slice(open + 1, close)) ?? false;
    i = close + 1;
  }
  return { securityInvoker, sources: relationsRead(masked, commentless, i) };
}

/**
 * The part of a CREATE or ALTER FUNCTION after the name and argument list, with strings and
 * bodies blanked so `security definer` inside a body doesn't count. Quoted identifiers stay,
 * because `supabase db dump` writes `RETURNS "trigger"` and `SET "search_path" TO ''`.
 */
function functionRest(stmt: SqlStatement, head: RegExp): string | null {
  const masked = maskSql(stmt.raw, true, true);
  const start = fromFirstToken(stmt, masked);
  const m = head.exec(masked.slice(start));
  if (!m) return null;
  let i = start + m[0].length;
  while (/\s/.test(masked[i] ?? "")) i++;
  if (masked[i] === "(") {
    const close = closingParen(masked, i);
    if (close < 0) return null;
    i = close + 1;
  }
  return masked.slice(i).replace(/\s+/g, " ").trim();
}

const SETS_SEARCH_PATH = /\bset\s+"?search_path\b/i;

function lastSecurity(rest: string): "definer" | "invoker" | undefined {
  const all = [...rest.matchAll(/\bsecurity\s+(definer|invoker)\b/gi)];
  return all.at(-1)?.[1]?.toLowerCase() as "definer" | "invoker" | undefined;
}

/** Function keys in `f(int, numeric(10, 2)), g`, with the argument lists removed. */
function functionNames(list: string): string[] {
  let s = list;
  for (let prev = ""; prev !== s; ) (prev = s), (s = s.replace(/\([^()]*\)/g, ""));
  return s
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => normaliseName(p).key);
}

function roleList(s: string): string[] {
  return s
    .replace(/\s+granted\s+by\s+.+$/i, "")
    .replace(/\s+(?:cascade|restrict)$/i, "")
    .split(",")
    .map(normaliseIdent)
    .filter((r) => r.length > 0);
}

/** File offset of the statement's own first token, past a DO block's `begin`. */
function tokenOffset(stmt: SqlStatement): number {
  return stmt.rawOffset + fromFirstToken(stmt, maskSql(stmt.raw, true));
}

function rekey<T extends { schema: string; name: string }>(map: Map<string, T>, key: string, schema: string, name: string) {
  const item = map.get(key);
  if (!item) return;
  map.delete(key);
  item.schema = schema;
  item.name = name;
  map.set(`${schema}.${name}`, item);
}

const SIMPLE_IDENT = /^[a-z_][a-z0-9_$]*$/;

/**
 * Postgres `format(fmt, v, v, …)` with the same value for all `nArgs` arguments. Handles
 * `%s`, `%I`, their positional forms (`%1$I`) and `%%`. Returns null for anything else
 * (`%L`, widths, a missing argument), so the caller treats the SQL as unknown.
 */
export function formatSql(fmt: string, nArgs: number, value: string): string | null {
  // quote_ident leaves plain lower-case names bare; keywords it would quote read the same here.
  const ident = SIMPLE_IDENT.test(value) ? value : `"${value.replace(/"/g, '""')}"`;
  let out = "";
  let next = 0;
  for (let i = 0; i < fmt.length; i++) {
    if (fmt[i] !== "%") {
      out += fmt[i];
      continue;
    }
    const m = /^%(?:%|(?:([1-9]\d*)\$)?([sI]))/.exec(fmt.slice(i));
    if (!m) return null;
    i += m[0].length - 1;
    if (m[0] === "%%") {
      out += "%";
      continue;
    }
    next = m[1] ? Number(m[1]) : next + 1;
    if (next > nArgs) return null;
    out += m[2] === "I" ? ident : value;
  }
  return out;
}

const STRING_LITERAL = /^'((?:[^']|'')*)'$/;
const DOLLAR_LITERAL = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$([\s\S]*)\$\1\$$/;

/** The text of a plain `'…'` or dollar-quoted string literal, or null. */
function literalText(s: string): string | null {
  const q = STRING_LITERAL.exec(s);
  if (q) return q[1]!.replace(/''/g, "'");
  return DOLLAR_LITERAL.exec(s)?.[2] ?? null;
}
const FOREACH_LITERAL = new RegExp(
  String.raw`\bforeach\s+(${IDENT})\s+in\s+array\s+array\s*\[[^\]]*\]\s*(?:::\s*(?:text|varchar|name)\s*\[\s*\]\s*)?$`,
  "i",
);

/**
 * Reads a DO block body for `execute` statements. In `foreach v in array array['a', …] loop`
 * (top level, every element a string literal), `execute format('<literal>', v, …)` (or a
 * dollar-quoted format string) is expanded
 * into the SQL it runs for each element, in the order Postgres runs it. Every other `execute`
 * is returned as unknown, but only when the block mentions row level security at all.
 */
function doBlockExecutes(body: string, base: number) {
  const masked = maskSql(body, true);
  const commentless = maskSql(body, false);
  const expanded: Array<{ at: number; stmts: Array<{ stmt: SqlStatement; pin: number }> }> = [];
  const unknown: number[] = [];

  // Loop spans, from the `loop` keyword to its `end loop`.
  const loops: Array<{ head: number; bodyStart: number; end: number; top: boolean }> = [];
  const stack: Array<{ head: number; bodyStart: number }> = [];
  for (const m of masked.matchAll(/\b(end\s+loop|loop)\b/gi)) {
    if (/^end/i.test(m[1]!)) {
      const open = stack.pop();
      if (open) loops.push({ ...open, end: m.index, top: stack.length === 0 });
    } else stack.push({ head: m.index, bodyStart: m.index + m[0].length });
  }

  const executes: number[] = [];
  for (const m of masked.matchAll(/\bexecute\b/gi)) {
    if (/(?:^|;|\b(?:begin|loop|then|else)|>>)\s*$/i.test(masked.slice(0, m.index))) executes.push(m.index);
  }
  const handled = new Set<number>();
  for (const loop of loops) {
    if (!loop.top) continue;
    const headStart = masked.lastIndexOf(";", loop.head) + 1;
    const head = FOREACH_LITERAL.exec(masked.slice(headStart, loop.head));
    if (!head) continue;
    const open = headStart + head.index + head[0].indexOf("[");
    const values: string[] = [];
    for (const [a, b] of topLevelCommas(masked, open + 1, masked.indexOf("]", open))) {
      const lit = STRING_LITERAL.exec(commentless.slice(a, b).trim());
      if (!lit) {
        values.length = 0;
        break;
      }
      values.push(lit[1]!.replace(/''/g, "'"));
    }
    if (values.length === 0) continue;
    const loopVar = normaliseIdent(head[1]!);
    const inLoop = executes.filter(
      (x) => x > loop.bodyStart && x < loop.end && !loops.some((l) => !l.top && x > l.bodyStart && x < l.end),
    );
    const formats: Array<{ at: number; fmt: string; n: number }> = [];
    for (const x of inLoop) {
      const semi = masked.indexOf(";", x);
      const end = semi < 0 ? masked.length : semi;
      const fm = /^execute\s+format\s*\(/i.exec(masked.slice(x, end));
      const paren = fm ? x + fm[0].length - 1 : -1;
      const close = fm ? closingParen(masked, paren) : -1;
      if (close < 0 || close > end || masked.slice(close + 1, end).trim() !== "") continue;
      const [first, ...rest] = topLevelCommas(masked, paren + 1, close).map(([a, b]) => commentless.slice(a, b).trim());
      const fmt = literalText(first ?? "");
      const varOnly = rest.length > 0 && rest.every((r) => new RegExp(`^${IDENT}$`).test(r) && normaliseIdent(r) === loopVar);
      if (fmt === null || !varOnly) continue;
      if (values.some((v) => formatSql(fmt, rest.length, v) === null)) continue;
      formats.push({ at: base + x, fmt, n: rest.length });
      handled.add(x);
    }
    const stmts = values.flatMap((v) =>
      formats.flatMap((f) => splitStatements(formatSql(f.fmt, f.n, v)!).map((stmt) => ({ stmt, pin: f.at }))),
    );
    if (stmts.length > 0) expanded.push({ at: base + loop.end, stmts });
  }
  if (/\brow\s+level\s+security\b/i.test(commentless)) {
    for (const x of executes) if (!handled.has(x)) unknown.push(base + x);
  }
  return { expanded, unknown };
}

/** Replays every migration in order and returns the final state of each table, view and function. */
export function replayMigrations(project: ProjectFiles): MigrationState {
  const tables = new Map<string, TableState>();
  const views = new Map<string, ViewState>();
  const functions = new Map<string, FunctionState>();
  const revoked = new Map<string, Set<string>>();
  /** EXECUTE revoked by `alter default privileges`, by schema ("*" for every schema). */
  const defaultRevoked = new Map<string, Set<string>>();
  const files = migrationFiles(project);

  /** `pin`: the statement was expanded from a DO block's `execute`, so report everything at that offset. */
  const apply = (stmt: SqlStatement, file: string, pin?: number) => {
    const at = (offset: number) => pin ?? offset;
    // Inside DO blocks and functions, the first statement carries the block's `begin`.
    const t = stmt.text.replace(/^begin\s+(?!transaction|work)/i, "");
    let m: RegExpExecArray | null;

    if (/^do\b/i.test(t)) {
      const body = dollarBody(stmt);
      if (!body) return;
      const { expanded, unknown } = doBlockExecutes(body.body, body.offset);
      const steps: Array<{ at: number; run: () => void }> = [
        ...splitStatements(body.body, body.offset).map((inner) => ({ at: inner.offset, run: () => apply(inner, file, pin) })),
        ...expanded.map((e) => ({ at: e.at, run: () => e.stmts.forEach((x) => apply(x.stmt, file, pin ?? x.pin)) })),
        ...unknown.map((offset) => ({
          at: offset,
          run: () => {
            for (const tbl of tables.values()) if (!tbl.rlsEnabled) tbl.rlsDynamic ??= { file, offset: pin ?? offset };
          },
        })),
      ];
      for (const s of steps.sort((a, b) => a.at - b.at)) s.run();
      return;
    }
    if ((m = CREATE_VIEW.exec(t))) {
      if (m[1]) return; // temporary views live in a session's own schema
      const { schema, name, key } = normaliseName(m[2]!);
      // CREATE OR REPLACE VIEW replaces the options too, so an earlier ALTER VIEW SET is lost.
      views.set(key, { schema, name, file, offset: at(tokenOffset(stmt)), ...viewParts(stmt), apiRevoked: false });
      return;
    }
    if ((m = ALTER_VIEW.exec(t))) {
      const from = normaliseName(m[1]!);
      const view = views.get(from.key);
      if (!view) return;
      if (m[3]) rekey(views, from.key, view.schema, normaliseName(m[3]).name);
      else if (m[4]) rekey(views, from.key, normaliseIdent(m[4]), view.name);
      else {
        const opt = invokerOption(t.slice(m.index + m[0].length));
        if (opt !== undefined) view.securityInvoker = /^set/i.test(m[2]!) ? opt : false;
      }
      return;
    }
    if ((m = DROP_VIEW.exec(t))) {
      for (const part of m[1]!.split(",")) views.delete(normaliseName(part.trim()).key);
      return;
    }
    if ((m = CREATE_FUNCTION.exec(t))) {
      const { schema, name, key } = normaliseName(m[1]!);
      const rest = functionRest(stmt, CREATE_FUNCTION);
      if (rest === null) return;
      // CREATE OR REPLACE keeps the function's privileges; a new function starts from the defaults.
      const revokedNow = functions.get(key)?.revoked ?? new Set([...(defaultRevoked.get("*") ?? []), ...(defaultRevoked.get(schema) ?? [])]);
      functions.set(key, {
        schema,
        name,
        file,
        offset: at(tokenOffset(stmt)),
        securityDefiner: lastSecurity(rest) === "definer",
        searchPath: SETS_SEARCH_PATH.test(rest),
        returnsTrigger: /\breturns\s+"?(?:trigger|event_trigger)\b/i.test(rest),
        revoked: revokedNow,
      });
      return;
    }
    if ((m = ALTER_FUNCTION.exec(t))) {
      const from = normaliseName(m[1]!);
      const fn = functions.get(from.key);
      const rest = fn ? functionRest(stmt, ALTER_FUNCTION) : null;
      if (!fn || rest === null) return;
      const security = lastSecurity(rest);
      if (security) fn.securityDefiner = security === "definer";
      if (SETS_SEARCH_PATH.test(rest)) fn.searchPath = true;
      if (/\breset\s+(?:"?search_path\b|all\b)/i.test(rest)) fn.searchPath = false;
      const rename = new RegExp(String.raw`^rename\s+to\s+(${IDENT})`, "i").exec(rest);
      const move = new RegExp(String.raw`^set\s+schema\s+(${IDENT})`, "i").exec(rest);
      if (rename) rekey(functions, from.key, fn.schema, normaliseIdent(rename[1]!));
      if (move) rekey(functions, from.key, normaliseIdent(move[1]!), fn.name);
      return;
    }
    if ((m = DROP_FUNCTION.exec(t))) {
      for (const key of functionNames(m[1]!)) functions.delete(key);
      return;
    }
    if ((m = FUNCTION_PRIVILEGE.exec(t))) {
      if (!/\b(?:execute|all)\b/i.test(m[2]!)) return;
      const schemas = m[4]?.split(",").map(normaliseIdent);
      const targets = m[3]
        ? functionNames(m[3]).flatMap((k) => functions.get(k) ?? [])
        : [...functions.values()].filter((f) => schemas!.includes(f.schema));
      const revoke = m[1]!.toLowerCase() === "revoke";
      for (const fn of targets) for (const role of roleList(m[5]!)) revoke ? fn.revoked.add(role) : fn.revoked.delete(role);
      return;
    }
    if ((m = DEFAULT_PRIVILEGE.exec(t))) {
      if (!/\b(?:execute|all)\b/i.test(m[3]!)) return;
      const revoke = m[2]!.toLowerCase() === "revoke";
      for (const schema of m[1] ? m[1].split(",").map(normaliseIdent) : ["*"]) {
        const set = defaultRevoked.get(schema) ?? new Set<string>();
        for (const role of roleList(m[4]!)) revoke ? set.add(role) : set.delete(role);
        defaultRevoked.set(schema, set);
      }
      return;
    }
    if ((m = CREATE_TABLE.exec(t))) {
      const { schema, name, key } = normaliseName(m[2]!);
      if (!tables.has(key)) {
        tables.set(key, {
          schema,
          name,
          file,
          offset: at(stmt.offset),
          rlsEnabled: false,
          apiRevoked: false,
          temporary: /^temp/i.test(m[1] ?? ""),
          ownerColumns: ownerColumnsOf(stmt),
          policies: new Map(),
        });
      }
      return;
    }
    if ((m = CREATE_POLICY.exec(t))) {
      const tbl = tables.get(normaliseName(m[2]!).key);
      if (!tbl) return;
      const parts = policyParts(stmt, file, pin);
      const name = normaliseIdent(m[1]!);
      tbl.policies.set(name, {
        name,
        permissive: parts.permissive,
        command: parts.command ?? "all",
        roles: parts.roles ?? ["public"],
        using: parts.using,
        check: parts.check,
        file,
        offset: at(stmt.offset),
      });
      return;
    }
    if ((m = ALTER_POLICY.exec(t))) {
      const tbl = tables.get(normaliseName(m[2]!).key);
      const pol = tbl?.policies.get(normaliseIdent(m[1]!));
      if (!tbl || !pol) return;
      if (m[3]) {
        tbl.policies.delete(pol.name);
        pol.name = normaliseIdent(m[3]);
        tbl.policies.set(pol.name, pol);
        return;
      }
      const parts = policyParts(stmt, file, pin);
      if (parts.roles) pol.roles = parts.roles;
      if (parts.using) pol.using = parts.using;
      if (parts.check) pol.check = parts.check;
      return;
    }
    if ((m = DROP_POLICY.exec(t))) {
      tables.get(normaliseName(m[2]!).key)?.policies.delete(normaliseIdent(m[1]!));
      return;
    }
    if ((m = ADD_COLUMN.exec(t))) {
      const tbl = tables.get(normaliseName(m[1]!).key);
      if (!tbl) return;
      for (const part of t.slice(m[0].length - 1).split(/,\s*add\s/i)) {
        const el = part.trim().replace(/^column\s+/i, "").replace(/^if\s+not\s+exists\s+/i, "");
        // `supabase db dump` adds foreign keys separately: ADD CONSTRAINT … FOREIGN KEY (…) REFERENCES auth.users.
        const fk = new RegExp(String.raw`^(?:constraint\s+${IDENT}\s+)?foreign\s+key\s*\(([^)]*)\)`, "i").exec(el);
        if (fk) {
          if (REFERENCES_AUTH_USERS.test(el)) {
            for (const c of fk[1]!.split(",").map(normaliseIdent)) if (!tbl.ownerColumns.includes(c)) tbl.ownerColumns.push(c);
          }
          continue;
        }
        if (/^(constraint|primary|unique|check|foreign)\b/i.test(el)) continue;
        const col = new RegExp(`^${IDENT}`).exec(el)?.[0];
        if (!col) continue;
        const name = normaliseIdent(col);
        if ((REFERENCES_AUTH_USERS.test(el) || OWNER_NAME.test(name)) && !tbl.ownerColumns.includes(name)) {
          tbl.ownerColumns.push(name);
        }
      }
      return;
    }
    if ((m = ALTER_RLS.exec(t))) {
      const tbl = tables.get(normaliseName(m[1]!).key);
      if (tbl) {
        tbl.rlsEnabled = m[2]!.toLowerCase() === "enable";
        tbl.rlsDynamic = undefined;
      }
      return;
    }
    if ((m = RENAME.exec(t))) {
      const from = normaliseName(m[1]!);
      const tbl = tables.get(from.key);
      if (tbl) {
        tables.delete(from.key);
        tbl.name = normaliseName(m[2]!).name; // RENAME TO never changes the schema
        tables.set(`${tbl.schema}.${tbl.name}`, tbl);
      }
      return;
    }
    if ((m = SET_SCHEMA.exec(t))) {
      const from = normaliseName(m[1]!);
      const tbl = tables.get(from.key);
      if (tbl) {
        tables.delete(from.key);
        tbl.schema = normaliseName(m[2]!).name;
        tables.set(`${tbl.schema}.${tbl.name}`, tbl);
      }
      return;
    }
    if ((m = DROP.exec(t))) {
      for (const part of m[1]!.split(",")) tables.delete(normaliseName(part.trim()).key);
      return;
    }
    if ((m = REVOKE.exec(t))) {
      const roles = m[2]!.toLowerCase();
      for (const part of m[1]!.split(",")) {
        const key = normaliseName(part.trim()).key;
        const set = revoked.get(key) ?? new Set<string>();
        if (/\bpublic\b/.test(roles)) (set.add("anon"), set.add("authenticated"));
        if (/\banon\b/.test(roles)) set.add("anon");
        if (/\bauthenticated\b/.test(roles)) set.add("authenticated");
        revoked.set(key, set);
      }
    }
  };

  for (const file of files) {
    const text = project.read(file);
    if (!text) continue;
    for (const stmt of splitStatements(text)) apply(stmt, file);
  }

  for (const [key, tbl] of tables) {
    const r = revoked.get(key);
    tbl.apiRevoked = !!r && r.has("anon") && r.has("authenticated");
  }
  for (const [key, view] of views) {
    const r = revoked.get(key);
    view.apiRevoked = !!r && r.has("anon") && r.has("authenticated");
  }
  return { tables, views, functions, files };
}
