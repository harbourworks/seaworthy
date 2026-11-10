import type { Node } from "@babel/types";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";
import { MODEL_OUTPUT_RE, SANITISER_RE, analyseTaint, stringParts } from "../taint.js";

/** SQL-running methods (as in SW-A05). */
const SQL_METHODS = new Set(["query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "exec"]);

type Sink = "html" | "code" | "sql";

const WHAT: Record<Sink, { title: string; risk: string; fix: string }> = {
  html: {
    title: "Model output rendered as HTML",
    risk:
      "Anyone who can influence the model's input, including through a web page or document it reads, can make " +
      "it return a `<script>` or an `<img onerror>` that runs in your users' browsers, with their session.",
    fix:
      "Render model output as text (React escapes `{reply}` for you), or as Markdown without raw HTML. If you " +
      "must allow HTML, pass it through DOMPurify first: `DOMPurify.sanitize(reply)`.",
  },
  code: {
    title: "Model output run as code",
    risk: "Whatever the model returns runs with your app's permissions, and model output can be steered by its input.",
    fix: "Never evaluate model output. Have the model return structured data (JSON with a schema) and act on that with your own code.",
  },
  sql: {
    title: "Model output used in a SQL query",
    risk: "A model can be steered into returning SQL that reads or deletes data it shouldn't.",
    fix:
      "Don't run model-written SQL. Have the model choose from queries you wrote (with parameters), or run it " +
      "through a read-only database user limited to the tables it needs.",
  },
};

export const l02ModelOutputSink: Rule = {
  id: "SW-L02",
  title: "Model output rendered as HTML or run as code",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "Treat model output like user input: an attacker can steer it, directly or through content the model " +
      "reads. Rendering it as HTML is an XSS hole, and passing it to `eval` or a SQL query runs whatever it " +
      "says. (Model-chosen shell commands are covered by SW-L03.)",
    bad: `<div dangerouslySetInnerHTML={{ __html: completion.choices[0].message.content }} />`,
    good: `<div>{completion.choices[0].message.content}</div>  {/* rendered as text */}`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text || !MODEL_OUTPUT_RE.test(text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const { isTainted, builders } = analyseTaint(ast, text, { source: MODEL_OUTPUT_RE, sanitiser: SANITISER_RE });
      const report = (sink: Sink, at: Node) => {
        const w = WHAT[sink];
        out.push({
          file,
          ...project.position(file, at.start ?? 0),
          title: w.title,
          why: `This passes text from an LLM straight into ${sink === "html" ? "the page as HTML" : sink === "code" ? "code execution" : "a SQL query"}. ${w.risk}`,
          fix: w.fix,
          fixPrompt:
            `In ${file}, LLM output is ${sink === "html" ? "rendered as raw HTML" : sink === "code" ? "evaluated as code" : "used in a SQL query"}. ` +
            `Change it so the output is treated as untrusted data: ${w.fix}`,
        });
      };
      const taintedOrBuilt = (e: Node) => {
        const v = e.type === "Identifier" && builders.has(e.name) ? builders.get(e.name)! : e;
        const parts = stringParts(v);
        return parts ? parts.exprs.some(isTainted) : isTainted(v);
      };

      walkAst(ast, (n) => {
        // <div dangerouslySetInnerHTML={{ __html: x }} />
        if (n.type === "JSXAttribute" && n.name.type === "JSXIdentifier" && n.name.name === "dangerouslySetInnerHTML") {
          const v = n.value?.type === "JSXExpressionContainer" ? n.value.expression : null;
          if (v?.type === "ObjectExpression") {
            for (const p of v.properties) {
              if (p.type === "ObjectProperty" && p.key.type === "Identifier" && p.key.name === "__html" && isTainted(p.value as Node)) {
                report("html", n);
              }
            }
          }
          return;
        }
        // el.innerHTML = x
        if (n.type === "AssignmentExpression" && n.left.type === "MemberExpression" && n.left.property.type === "Identifier" &&
            /^(innerHTML|outerHTML)$/.test(n.left.property.name) && isTainted(n.right)) {
          report("html", n);
          return;
        }
        if (n.type === "CallExpression" || n.type === "NewExpression") {
          const c = n.callee;
          const args = n.arguments as Node[];
          const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : "";
          if (name === "insertAdjacentHTML" && args[1] && isTainted(args[1])) report("html", n);
          else if (name === "write" && c.type === "MemberExpression" && c.object.type === "Identifier" && c.object.name === "document" && args[0] && isTainted(args[0])) report("html", n);
          else if ((name === "eval" || name === "Function") && args.some((a) => isTainted(a))) report("code", n);
          else if (/^runIn(New|This)?Context$/.test(name) && args[0] && isTainted(args[0])) report("code", n);
          else if (SQL_METHODS.has(name) && c.type === "MemberExpression" && args[0] && taintedOrBuilt(args[0]) && !isChildProcess(c, text)) {
            report("sql", n);
          }
        }
      });
    }
    return out;
  },
};

/** `exec` from child_process is SW-L03's: model-chosen shell commands. */
function isChildProcess(callee: Node, text: string): boolean {
  return callee.type === "MemberExpression" && callee.object.type === "Identifier" &&
    /^(child_process|cp|childProcess)$/.test(callee.object.name) && /child_process/.test(text);
}
