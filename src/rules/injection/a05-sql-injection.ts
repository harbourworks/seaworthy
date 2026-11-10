import type { Node } from "@babel/types";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";
import { REQUEST_INPUT_RE, analyseTaint, stringParts } from "../taint.js";

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
      const { isTainted, builders } = analyseTaint(ast, text, {
        source: REQUEST_INPUT_RE,
        allParams: /^\s*["']use server["']/m.test(text), // every server action argument comes from the client
        routeParams: true,
      });

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

function short(s: string): string {
  const one = s.replace(/\s+/g, " ");
  return one.length > 50 ? `${one.slice(0, 47)}...` : one;
}
