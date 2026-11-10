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

export interface MigrationState {
  tables: Map<string, TableState>;
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
function policyParts(stmt: SqlStatement, file: string) {
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
    const clause = { expr: inner.replace(/\s+/g, " ").trim(), offset: stmt.rawOffset + open + 1 + lead, file };
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

/** Replays every migration in order and returns the final state of each table. */
export function replayMigrations(project: ProjectFiles): MigrationState {
  const tables = new Map<string, TableState>();
  const revoked = new Map<string, Set<string>>();
  const files = migrationFiles(project);

  const apply = (stmt: SqlStatement, file: string) => {
    // Inside DO blocks and functions, the first statement carries the block's `begin`.
    const t = stmt.text.replace(/^begin\s+(?!transaction|work)/i, "");
    let m: RegExpExecArray | null;

    if (/^do\b/i.test(t)) {
      const body = dollarBody(stmt);
      if (body) for (const inner of splitStatements(body.body, body.offset)) apply(inner, file);
      return;
    }
    if ((m = CREATE_TABLE.exec(t))) {
      const { schema, name, key } = normaliseName(m[2]!);
      if (!tables.has(key)) {
        tables.set(key, {
          schema,
          name,
          file,
          offset: stmt.offset,
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
      const parts = policyParts(stmt, file);
      const name = normaliseIdent(m[1]!);
      tbl.policies.set(name, {
        name,
        permissive: parts.permissive,
        command: parts.command ?? "all",
        roles: parts.roles ?? ["public"],
        using: parts.using,
        check: parts.check,
        file,
        offset: stmt.offset,
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
      const parts = policyParts(stmt, file);
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
      if (tbl) tbl.rlsEnabled = m[2]!.toLowerCase() === "enable";
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
  return { tables, files };
}
