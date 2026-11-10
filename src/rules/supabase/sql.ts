/**
 * Small, dependency-free reader for Postgres migration files. It does not build a full AST:
 * it splits a file into statements correctly (respecting strings, quoted identifiers,
 * dollar-quoted bodies and comments), then exposes each statement with comments stripped so
 * rules can match the handful of statement shapes they care about.
 */

export interface SqlStatement {
  /** Offset in the file of the statement's first real token. */
  offset: number;
  /** Statement text with comments removed and whitespace collapsed. Original case. */
  text: string;
  /** Raw source, including comments, for offset arithmetic. */
  raw: string;
  /** Offset in the file where `raw` begins. */
  rawOffset: number;
}

export function splitStatements(sql: string, baseOffset = 0): SqlStatement[] {
  const out: SqlStatement[] = [];
  let start = 0;
  let clean = "";
  let firstTokenAt = -1;
  let i = 0;
  const n = sql.length;

  const flush = (end: number) => {
    const text = clean.replace(/\s+/g, " ").trim();
    if (text.length > 0 && firstTokenAt >= 0) {
      out.push({ offset: baseOffset + firstTokenAt, text, raw: sql.slice(start, end), rawOffset: baseOffset + start });
    }
    clean = "";
    firstTokenAt = -1;
    start = end + 1;
  };
  const mark = (pos: number) => {
    if (firstTokenAt < 0) firstTokenAt = pos;
  };

  while (i < n) {
    const c = sql[i]!;
    const next = sql[i + 1];

    if (c === "-" && next === "-") {
      while (i < n && sql[i] !== "\n") i++;
      clean += " ";
      continue;
    }
    if (c === "/" && next === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") (depth++, (i += 2));
        else if (sql[i] === "*" && sql[i + 1] === "/") (depth--, (i += 2));
        else i++;
      }
      clean += " ";
      continue;
    }
    if (c === "'" || ((c === "E" || c === "e") && next === "'" && !isIdentChar(sql[i - 1]))) {
      mark(i);
      const backslashEscapes = c !== "'";
      const s = i;
      i += c === "'" ? 1 : 2;
      while (i < n) {
        if (backslashEscapes && sql[i] === "\\") {
          i += 2;
          continue;
        }
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      clean += sql.slice(s, i);
      continue;
    }
    if (c === '"') {
      mark(i);
      const s = i;
      i++;
      while (i < n) {
        if (sql[i] === '"') {
          if (sql[i + 1] === '"') {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      clean += sql.slice(s, i);
      continue;
    }
    if (c === "$" && !isIdentChar(sql[i - 1])) {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        mark(i);
        const close = sql.indexOf(tag[0], i + tag[0].length);
        const end = close < 0 ? n : close + tag[0].length;
        clean += sql.slice(i, end);
        i = end;
        continue;
      }
    }
    if (c === ";") {
      flush(i);
      i++;
      continue;
    }
    if (!/\s/.test(c)) mark(i);
    clean += c;
    i++;
  }
  flush(n);
  return out;
}

function isIdentChar(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9_$]/.test(ch);
}

/** An identifier, quoted or not. */
export const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
/** `schema.table` or `table`. */
export const QNAME = String.raw`${IDENT}(?:\s*\.\s*${IDENT})?`;

/** Normalises `Public."Notes"` to `public.Notes`. Unqualified names default to `public`. */
export function normaliseName(qname: string): { schema: string; name: string; key: string } {
  const parts: string[] = [];
  const re = new RegExp(IDENT, "g");
  for (const m of qname.matchAll(re)) {
    const p = m[0];
    parts.push(p.startsWith('"') ? p.slice(1, -1).replace(/""/g, '"') : p.toLowerCase());
  }
  const [a, b] = parts;
  const schema = b !== undefined ? a! : "public";
  const name = b !== undefined ? b : a!;
  return { schema, name, key: `${schema}.${name}` };
}

/** Body of a `DO $$ … $$` block, or of a function, with its offset in the file. */
export function dollarBody(stmt: SqlStatement): { body: string; offset: number } | null {
  const m = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(stmt.raw);
  if (!m) return null;
  const open = m.index + m[0].length;
  const close = stmt.raw.indexOf(m[0], open);
  if (close < 0) return null;
  return { body: stmt.raw.slice(open, close), offset: stmt.rawOffset + open };
}

/**
 * Returns `sql` with comments replaced by spaces, keeping every offset and newline. With
 * `blankLiterals`, the insides of strings, quoted identifiers and dollar-quoted bodies are
 * blanked too, so keyword and parenthesis searches only see real SQL structure.
 */
export function maskSql(sql: string, blankLiterals: boolean): string {
  const out = sql.split("");
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i]!;
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      const s = i;
      while (i < n && sql[i] !== "\n") i++;
      blank(s, i);
      continue;
    }
    if (c === "/" && next === "*") {
      const s = i;
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") (depth++, (i += 2));
        else if (sql[i] === "*" && sql[i + 1] === "/") (depth--, (i += 2));
        else i++;
      }
      blank(s, i);
      continue;
    }
    if (c === "'" || c === '"' || ((c === "E" || c === "e") && next === "'" && !isIdentChar(sql[i - 1]))) {
      const q = c === '"' ? '"' : "'";
      const backslashEscapes = c === "E" || c === "e";
      i += c === "E" || c === "e" ? 2 : 1;
      const s = i;
      while (i < n) {
        if (backslashEscapes && sql[i] === "\\") {
          i += 2;
          continue;
        }
        if (sql[i] === q) {
          if (sql[i + 1] === q) {
            i += 2;
            continue;
          }
          break;
        }
        i++;
      }
      if (blankLiterals) blank(s, Math.min(i, n));
      i++;
      continue;
    }
    if (c === "$" && !isIdentChar(sql[i - 1])) {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        const open = i + tag[0].length;
        const close = sql.indexOf(tag[0], open);
        const end = close < 0 ? n : close;
        if (blankLiterals) blank(open, end);
        i = close < 0 ? n : close + tag[0].length;
        continue;
      }
    }
    i++;
  }
  return out.join("");
}

/** Index of the parenthesis that closes the one at `open`, in text from `maskSql(…, true)`. */
export function closingParen(masked: string, open: number): number {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === "(") depth++;
    else if (masked[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

/** Splits text from `maskSql(…, true)` at commas that are not inside parentheses. Returns [start, end) ranges. */
export function topLevelCommas(masked: string, from: number, to: number): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let depth = 0;
  let start = from;
  for (let i = from; i < to; i++) {
    const ch = masked[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) (out.push([start, i]), (start = i + 1));
  }
  out.push([start, to]);
  return out;
}

/** Normalises one identifier: quoted keeps its case, unquoted is lower-cased. */
export function normaliseIdent(ident: string): string {
  const t = ident.trim();
  return t.startsWith('"') ? t.slice(1, -1).replace(/""/g, '"') : t.toLowerCase();
}
