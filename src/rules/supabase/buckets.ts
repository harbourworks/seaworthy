import { posix } from "node:path";
import type { ProjectFiles } from "../../core/project.js";
import { codeFiles } from "../code.js";
import { splitStatements } from "./sql.js";

/**
 * Supabase storage buckets marked public, from the three places projects create them:
 * SQL (migrations and seed.sql, replayed in order), supabase/config.toml, and
 * createBucket / updateBucket calls in code.
 */
export interface PublicBucket {
  id: string;
  file: string;
  offset: number;
  source: "sql" | "config" | "code";
}

const SQL_FILE = /(^|\/)supabase\/(migrations\/[^/]+\.sql|schema\.sql|seed\.sql)$/i;

export function publicBuckets(project: ProjectFiles): PublicBucket[] {
  const out = new Map<string, PublicBucket>();

  // SQL: migrations in filename order, then seed.sql (it runs after them).
  const sqlFiles = project.files
    .filter((f) => SQL_FILE.test(f))
    .sort((a, b) => Number(/seed\.sql$/i.test(a)) - Number(/seed\.sql$/i.test(b)) || a.localeCompare(b));
  for (const file of sqlFiles) {
    const text = project.read(file);
    if (!text) continue;
    for (const st of splitStatements(text)) {
      const at = (id: string) => {
        const i = st.raw.indexOf(`'${id}'`);
        return st.rawOffset + (i >= 0 ? i : 0);
      };
      const ins = /^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$/i.exec(st.text);
      if (ins) {
        const cols = ins[1]!.split(",").map((c) => c.trim().replace(/"/g, "").toLowerCase());
        const idCol = cols.indexOf("id") >= 0 ? cols.indexOf("id") : cols.indexOf("name");
        const pubCol = cols.indexOf("public");
        for (const row of tuples(ins[2]!)) {
          const id = unquote(row[idCol] ?? "");
          if (!id) continue;
          if (pubCol >= 0 && isTrue(row[pubCol] ?? "")) out.set(id, { id, file, offset: at(id), source: "sql" });
          else out.delete(id);
        }
        continue;
      }
      const upd = /^update\s+storage\s*\.\s*buckets\s+set\s+(.*?)(?:\s+where\s+(.*))?$/i.exec(st.text);
      if (upd) {
        const pub = /\bpublic\s*=\s*('?\w+'?)/i.exec(upd[1]!);
        if (!pub) continue;
        const target = upd[2] ? /\b(?:id|name)\s*=\s*'([^']+)'/i.exec(upd[2])?.[1] : undefined;
        const ids = target ? [target] : upd[2] ? [] : [...out.keys()];
        for (const id of ids) {
          if (isTrue(pub[1]!)) out.set(id, { id, file, offset: at(id), source: "sql" });
          else out.delete(id);
        }
        continue;
      }
      const del = /^delete\s+from\s+storage\s*\.\s*buckets\s+where\s+(?:id|name)\s*=\s*'([^']+)'/i.exec(st.text);
      if (del) out.delete(del[1]!);
    }
  }

  // supabase/config.toml: [storage.buckets.<name>] with public = true.
  for (const file of project.files.filter((f) => /(^|\/)supabase\/config\.toml$/.test(f))) {
    const text = project.read(file) ?? "";
    let bucket: { id: string; offset: number } | null = null;
    let offset = 0;
    for (const line of text.split("\n")) {
      const header = /^\s*\[\s*storage\.buckets\.(?:"([^"]+)"|([A-Za-z0-9_.-]+))\s*\]/.exec(line);
      if (header) bucket = { id: header[1] ?? header[2]!, offset: offset + line.indexOf("[") };
      else if (/^\s*\[/.test(line)) bucket = null;
      else if (bucket) {
        const pub = /^\s*public\s*=\s*(true|false)\b/.exec(line);
        if (pub?.[1] === "true") out.set(bucket.id, { id: bucket.id, file, offset: bucket.offset, source: "config" });
        else if (pub) out.delete(bucket.id);
      }
      offset += line.length + 1;
    }
  }

  // Code: storage.createBucket("name", { public: true }) and updateBucket.
  const CALL = /\.(?:createBucket|updateBucket)\(\s*(["'`])([^"'`$]+)\1\s*,\s*\{([^}]*)\}/g;
  for (const file of codeFiles(project)) {
    if (posix.basename(file).includes(".test.")) continue;
    const text = project.read(file);
    if (!text || !text.includes("Bucket(")) continue;
    for (const m of text.matchAll(CALL)) {
      if (/\bpublic\s*:\s*true\b/.test(m[3]!)) out.set(m[2]!, { id: m[2]!, file, offset: m.index!, source: "code" });
    }
  }
  return [...out.values()];
}

/** Bucket names that suggest private files, and names that suggest public ones. */
const SENSITIVE = /invoice|receipt|private|document|\bdocs?\b|contract|statement|kyc|identity|id[-_]?(card|scan|doc)|passport|licen[cs]e|medical|health|patient|payslip|payroll|\btax|bank|secure|confidential|personal|resume|\bcv\b|report|export|backup|record|legal|signature|verification/i;
const PUBLIC = /avatar|image|\bimg|photo|picture|media|public|asset|static|logo|banner|thumb|cover|product|icon|emoji|gallery|\bblog|\bposts?\b/i;

export function bucketSensitivity(id: string): "sensitive" | "public" | "unknown" {
  if (SENSITIVE.test(id)) return "sensitive";
  if (PUBLIC.test(id)) return "public";
  return "unknown";
}

const isTrue = (v: string) => /^(true|'t(rue)?'|'1'|1)$/i.test(v.trim());
const unquote = (v: string) => v.trim().replace(/^'(.*)'$/s, "$1").replace(/''/g, "'");

/** The value tuples after VALUES: [["'avatars'", "'avatars'", "true"], ...]. Strings, parens and brackets are respected. */
function tuples(s: string): string[][] {
  const rows: string[][] = [];
  let depth = 0;
  let row: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "'") {
      let j = i + 1;
      while (j < s.length && !(s[j] === "'" && s[j + 1] !== "'")) j += s[j] === "'" ? 2 : 1;
      if (depth > 0) cur += s.slice(i, j + 1);
      i = j;
      continue;
    }
    if (c === "(" || c === "[") {
      depth++;
      if (depth === 1 && c === "(") {
        row = [];
        cur = "";
        continue;
      }
    } else if (c === ")" || c === "]") {
      depth--;
      if (depth === 0 && c === ")") {
        row.push(cur.trim());
        rows.push(row);
        continue;
      }
    } else if (c === "," && depth === 1) {
      row.push(cur.trim());
      cur = "";
      continue;
    } else if (depth === 0 && /[a-z]/i.test(c)) {
      break; // ON CONFLICT, RETURNING: the values are over
    }
    if (depth > 0) cur += c;
  }
  return rows;
}
