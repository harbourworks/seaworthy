import type { Node } from "@babel/types";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";

/** Methods that run a SQL string as given. */
const SINK_METHODS = new Set([
  "query",
  "execute",
  "raw",
  "unsafe", // postgres.js sql.unsafe()
  "$queryRawUnsafe",
  "$executeRawUnsafe",
  "whereRaw",
  "orWhereRaw",
  "havingRaw",
  "orderByRaw",
  "groupByRaw",
  "joinRaw",
  "exec",
  "prepare",
]);
const SQL_WORDS = /\b(select\b[\s\S]*\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|where|order\s+by|values\s*\()/i;
/**
 * Expressions that are request input. Deliberately specific: passing `req` to a function
 * (`getUser(req)`) does not make its result user input.
 */
const SOURCE_RE =
  /\bsearchParams\b|\b(req|request)\.(query|body|params|cookies)\b|\b(req|request)\.(json|formData|text)\s*\(|\.headers\.get\s*\(|\bformData\.get\s*\(|\bcookies\(\)\.get\s*\(|\buseSearchParams\b/;

export const a05SqlInjection: Rule = {
  id: "SW-A05",
  title: "SQL built from user input",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "Gluing user input into a SQL string lets an attacker rewrite the query: a search box that " +
      "receives `' OR '1'='1` returns every row, and worse inputs can change or delete data. Pass " +
      "values as parameters instead, so the database never treats them as SQL.",
    bad: `const q = new URL(req.url).searchParams.get("q");\nawait pool.query("SELECT * FROM notes WHERE title ILIKE '%" + q + "%'");`,
    good: `const q = new URL(req.url).searchParams.get("q");\nawait pool.query("SELECT * FROM notes WHERE title ILIKE $1", [\`%\${q}%\`]);`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text || !SQL_WORDS.test(text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);
      const serverAction = /^\s*["']use server["']/m.test(text);
      const { tainted, builders } = collect(ast, src, serverAction);
      const isTainted = (expr: Node) => {
        if (SOURCE_RE.test(src(expr))) return true;
        let hit = false;
        walkAst(expr, (n) => {
          if (n.type === "Identifier" && tainted.has(n.name)) hit = true;
        });
        return hit;
      };

      walkAst(ast, (n) => {
        if (n.type !== "CallExpression") return;
        const c = n.callee;
        const method =
          c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : null;
        if (!method || !SINK_METHODS.has(method)) return;
        let arg = n.arguments[0] as Node | undefined;
        if (!arg) return;
        if (arg.type === "Identifier" && builders.has(arg.name)) arg = builders.get(arg.name)!;
        const parts = stringParts(arg);
        if (!parts || parts.exprs.length === 0 || !SQL_WORDS.test(parts.literal)) return;

        const bad = parts.exprs.find(isTainted);
        const at = bad ?? parts.exprs[0]!;
        const input = src(at);
        out.push({
          file,
          ...project.position(file, at.start ?? 0),
          // Values we can't trace to the request may still come from it, through a function argument.
          confidence: bad ? "high" : "medium",
          title: bad ? "SQL built from user input" : "SQL built by string concatenation",
          why: bad
            ? `\`${short(input)}\` comes from the request and is pasted into this SQL string. An attacker can send ` +
              `quotes and SQL in it to read other users' rows, change data or delete it.`
            : `This SQL string has \`${short(input)}\` pasted into it. Seaworthy couldn't tell where that value comes ` +
              `from; if any of it can come from a user, they can rewrite the query.`,
          fix:
            `Use placeholders and pass the values separately, for example ` +
            `\`${method}("… WHERE title ILIKE $1", ["%" + q + "%"])\` (use \`?\` for MySQL and SQLite). ` +
            `With Prisma, write \`$queryRaw\` as a tagged template; with postgres.js, use the \`sql\` tagged template instead of \`sql.unsafe\`.`,
          fixPrompt:
            `In ${file}, a SQL query is built by pasting \`${short(input)}\` into the string passed to ${method}(). ` +
            `Rewrite it as a parameterised query using my database library's placeholders, passing every value ` +
            `separately, and keep the behaviour the same.`,
        });
      });
    }
    return out;
  },
};

/** Literal text and inserted expressions of a string built with `+` or an untagged template. */
function stringParts(n: Node): { literal: string; exprs: Node[] } | null {
  if (n.type === "TemplateLiteral") {
    return { literal: n.quasis.map((q) => q.value.cooked ?? q.value.raw).join(" "), exprs: n.expressions as Node[] };
  }
  if (n.type === "BinaryExpression" && n.operator === "+") {
    const l = stringParts(n.left as Node) ?? leaf(n.left as Node);
    const r = stringParts(n.right) ?? leaf(n.right);
    return { literal: `${l.literal} ${r.literal}`, exprs: [...l.exprs, ...r.exprs] };
  }
  return null;
}

function leaf(n: Node): { literal: string; exprs: Node[] } {
  return n.type === "StringLiteral" ? { literal: n.value, exprs: [] } : { literal: "", exprs: [n] };
}

/**
 * Names holding request input, followed through simple assignments, and names holding a
 * built string (`const sql = "SELECT …" + x`) so a query called with `sql` is still checked.
 */
function collect(ast: Node, src: (n: Node) => string, serverAction: boolean) {
  const tainted = new Set<string>();
  const builders = new Map<string, Node>();
  const decls: Array<{ names: string[]; init: Node }> = [];

  walkAst(ast, (n) => {
    if (n.type === "VariableDeclarator" && n.init) {
      decls.push({ names: patternNames(n.id as Node), init: n.init });
      if (n.id.type === "Identifier" && stringParts(n.init)) builders.set(n.id.name, n.init);
    }
    // Route handlers' second argument, `{ params }`, and every server action argument are input.
    if (n.type === "FunctionDeclaration" || n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression") {
      const params = n.params as Node[];
      if (serverAction) for (const p of params) for (const name of patternNames(p)) tainted.add(name);
      for (const p of params) {
        if (p.type === "ObjectPattern" && patternNames(p).includes("params")) tainted.add("params");
      }
    }
  });

  // Follow assignments until nothing new is tainted.
  for (let changed = true; changed; ) {
    changed = false;
    for (const d of decls) {
      if (d.names.every((x) => tainted.has(x))) continue;
      let hit = SOURCE_RE.test(src(d.init));
      if (!hit) {
        walkAst(d.init, (n) => {
          if (n.type === "Identifier" && tainted.has(n.name)) hit = true;
        });
      }
      if (hit) {
        for (const x of d.names) tainted.add(x);
        changed = true;
      }
    }
  }
  return { tainted, builders };
}

function patternNames(p: Node): string[] {
  if (p.type === "Identifier") return [p.name];
  if (p.type === "ObjectPattern") {
    return p.properties.flatMap((prop) =>
      prop.type === "ObjectProperty" ? patternNames(prop.value as Node) : prop.type === "RestElement" ? patternNames(prop.argument) : [],
    );
  }
  if (p.type === "ArrayPattern") return p.elements.flatMap((e) => (e ? patternNames(e as Node) : []));
  if (p.type === "AssignmentPattern") return patternNames(p.left);
  if (p.type === "RestElement") return patternNames(p.argument);
  if (p.type === "TSParameterProperty") return patternNames(p.parameter as Node);
  return [];
}

function short(s: string): string {
  const one = s.replace(/\s+/g, " ");
  return one.length > 50 ? `${one.slice(0, 47)}...` : one;
}
