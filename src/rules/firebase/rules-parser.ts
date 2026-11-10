/**
 * A small reader for Firebase security rules (Firestore and Cloud Storage). It does not
 * evaluate rules; it finds each `allow` statement, the full match path it sits under, and
 * its condition, with zero-argument helper functions resolved, so rules can spot the
 * conditions that let everyone through.
 */

export interface AllowStatement {
  /** e.g. ["read", "write"]. */
  methods: string[];
  /** Condition after `if`, comments removed, whitespace collapsed. Null when there is none. */
  condition: string | null;
  /** The match path it sits under, joined: "/databases/{database}/documents/{document=**}". */
  path: string;
  /** File offset of the `allow` keyword. */
  offset: number;
}

export interface ParsedRules {
  service: string | null;
  allows: AllowStatement[];
}

/** Replaces comments with spaces and blanks string contents, keeping every offset. */
function mask(text: string): { structural: string; commentless: string } {
  const s = text.split("");
  const c = text.split("");
  const blank = (arr: string[], a: number, b: number) => {
    for (let k = a; k < b; k++) if (arr[k] !== "\n") arr[k] = " ";
  };
  let i = 0;
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === "//") {
      const a = i;
      while (i < text.length && text[i] !== "\n") i++;
      blank(s, a, i);
      blank(c, a, i);
    } else if (two === "/*") {
      const a = i;
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 2;
      blank(s, a, i);
      blank(c, a, i);
    } else if (text[i] === "'" || text[i] === '"') {
      const q = text[i]!;
      const a = ++i;
      while (i < text.length && text[i] !== q && text[i] !== "\n") i += text[i] === "\\" ? 2 : 1;
      blank(s, a, i);
      i++;
    } else i++;
  }
  return { structural: s.join(""), commentless: c.join("") };
}

export function parseRules(text: string): ParsedRules {
  const { structural, commentless } = mask(text);
  const allows: AllowStatement[] = [];
  const functions = new Map<string, string>();
  const stack: Array<{ kind: "service" | "match" | "other"; path: string }> = [];
  let service: string | null = null;
  const currentPath = () => stack.filter((b) => b.kind === "match").map((b) => b.path).join("");

  // An allow statement ends at `;`, or at the closing brace when the semicolon is left off.
  const re =
    /\bservice\s+([\w.]+)\s*\{|\bmatch\s+(\S+)\s*\{|\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{|\ballow\s+([\w\s,]+?)\s*(?::\s*if\b([^;}]*))?(?:;|(?=\}))|\{|\}/g;
  for (let m = re.exec(structural); m; m = re.exec(structural)) {
    if (m[1]) {
      service = m[1];
      stack.push({ kind: "service", path: "" });
    } else if (m[2]) {
      stack.push({ kind: "match", path: m[2] });
    } else if (m[3]) {
      // Capture a function body to its closing brace and remember single-return bodies.
      const open = m.index + m[0].length - 1;
      const close = matchingBrace(structural, open);
      const body = commentless.slice(open + 1, close < 0 ? structural.length : close);
      const ret = /^\s*return\s+([\s\S]*?);?\s*$/.exec(body);
      if (ret && m[4]!.trim() === "") functions.set(m[3], squash(ret[1]!));
      re.lastIndex = close < 0 ? structural.length : close + 1;
    } else if (m[5] !== undefined) {
      const condStart = m[6] !== undefined ? m.index + m[0].lastIndexOf(m[6]) : -1;
      const condition = m[6] !== undefined ? squash(commentless.slice(condStart, condStart + m[6].length)) : null;
      allows.push({
        methods: m[5].split(",").map((x) => x.trim()).filter(Boolean),
        condition,
        path: currentPath(),
        offset: m.index,
      });
    } else if (m[0] === "{") {
      stack.push({ kind: "other", path: "" });
    } else if (m[0] === "}") {
      stack.pop();
    }
  }

  // Resolve zero-argument helpers such as isSignedIn(), a few levels deep.
  for (const a of allows) {
    if (a.condition === null) continue;
    let cond: string = a.condition;
    for (let depth = 0; depth < 5; depth++) {
      const next: string = cond.replace(/\b(\w+)\(\s*\)/g, (call: string, name: string) =>
        functions.has(name) ? `(${functions.get(name)})` : call,
      );
      if (next === cond) break;
      cond = next;
    }
    a.condition = cond;
  }
  return { service, allows };
}

function matchingBrace(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function squash(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

export type Openness =
  | { kind: "everyone" }
  | { kind: "signed-in" }
  | { kind: "until"; date: Date };

/**
 * Whether a condition lets everyone through. Only plainly open conditions count: none at
 * all, `true`, "anyone signed in", or Firebase's test-mode `request.time < timestamp.date(…)`.
 * Anything that looks at the user or the data is a real rule and is left alone.
 */
export function openness(condition: string | null): Openness | null {
  if (condition === null) return { kind: "everyone" };
  let e = condition.replace(/\s+/g, "");
  while (/^\(.*\)$/.test(e) && balanced(e.slice(1, -1))) e = e.slice(1, -1);
  if (e === "true") return { kind: "everyone" };
  if (/^(request\.auth(\.uid)?!==?null|null!==?request\.auth(\.uid)?)$/.test(e)) return { kind: "signed-in" };
  const t = /^request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/.exec(e);
  if (t) return { kind: "until", date: new Date(Date.UTC(+t[1]!, +t[2]! - 1, +t[3]!)) };
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

/** Read and write, expanded from Firebase's granular methods. */
export function accessOf(methods: string[]): { reads: boolean; writes: boolean } {
  const reads = methods.some((m) => m === "read" || m === "get" || m === "list");
  const writes = methods.some((m) => m === "write" || m === "create" || m === "update" || m === "delete");
  return { reads, writes };
}

/** True if the path covers everything: a recursive wildcard with nothing fixed before it. */
export function coversEverything(path: string, root: RegExp): boolean {
  const rest = path.replace(root, "");
  return /^\/\{\w+=\*\*\}$/.test(rest);
}
