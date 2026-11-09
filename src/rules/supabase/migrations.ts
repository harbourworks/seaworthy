import type { ProjectFiles } from "../../core/project.js";
import { QNAME, dollarBody, normaliseName, splitStatements, type SqlStatement } from "./sql.js";

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
        });
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
