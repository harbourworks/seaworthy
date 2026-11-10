import { parse, type ParserPlugin } from "@babel/parser";
import type { Node } from "@babel/types";

/** JavaScript and TypeScript files Babel can parse directly. */
export const JS_FILE_RE = /\.(?:[cm]?[jt]sx?)$/;

function pluginsFor(file: string): ParserPlugin[] {
  if (/\.[cm]?ts$/.test(file)) return ["typescript"];
  if (/\.tsx$/.test(file)) return ["typescript", "jsx"];
  return ["jsx"];
}

/**
 * Parses a JS or TS file, tolerating errors so one odd line doesn't hide a whole file.
 * Returns null when Babel can't make sense of it at all; callers fall back to text matching.
 */
export function parseJs(file: string, text: string): Node | null {
  try {
    return parse(text, {
      sourceType: "unambiguous",
      plugins: pluginsFor(file),
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
    }).program;
  } catch {
    return null;
  }
}

/** Visits every node depth-first. Return false from `visit` to skip a node's children. */
export function walkAst(node: Node, visit: (n: Node, parent: Node | null) => boolean | void): void {
  const stack: Array<[Node, Node | null]> = [[node, null]];
  while (stack.length > 0) {
    const [n, parent] = stack.pop()!;
    if (visit(n, parent) === false) continue;
    const children: Node[] = [];
    for (const key of Object.keys(n)) {
      if (key === "loc" || key === "leadingComments" || key === "trailingComments" || key === "innerComments") continue;
      const v = (n as unknown as Record<string, unknown>)[key];
      if (Array.isArray(v)) {
        for (const c of v) if (isNode(c)) children.push(c);
      } else if (isNode(v)) children.push(v);
    }
    for (let i = children.length - 1; i >= 0; i--) stack.push([children[i]!, n]);
  }
}

/** `process.env` or `import.meta.env`. */
function isEnvObject(obj: Node): boolean {
  if ((obj.type !== "MemberExpression" && obj.type !== "OptionalMemberExpression") || obj.computed) return false;
  if (obj.property.type !== "Identifier" || obj.property.name !== "env") return false;
  const o = obj.object;
  return (o.type === "Identifier" && o.name === "process") || (o.type === "MetaProperty" && o.meta.name === "import");
}

/**
 * For files Babel can't parse (Vue, Svelte, Astro): true if `offset` is in code rather than
 * inside a comment or a string. A simple scanner, good enough to skip docs and examples.
 */
export function inCode(text: string, offset: number): boolean {
  let i = 0;
  let state: "code" | "line" | "block" | "html" | "'" | '"' | "`" = "code";
  while (i < offset) {
    const c = text[i]!;
    const two = text.slice(i, i + 2);
    if (state === "code") {
      if (two === "//") state = "line";
      else if (two === "/*") (state = "block"), i++;
      else if (text.startsWith("<!--", i)) (state = "html"), (i += 3);
      else if (c === "'" || c === '"' || c === "`") state = c;
    } else if (state === "line") {
      if (c === "\n") state = "code";
    } else if (state === "block") {
      if (two === "*/") (state = "code"), i++;
    } else if (state === "html") {
      if (text.startsWith("-->", i)) (state = "code"), (i += 2);
    } else {
      if (c === "\\") i++;
      else if (c === state || (c === "\n" && state !== "`")) state = "code";
    }
    i++;
  }
  return state === "code";
}

function isNode(v: unknown): v is Node {
  return typeof v === "object" && v !== null && typeof (v as { type?: unknown }).type === "string";
}

/**
 * Every `process.env.X`, `process.env["X"]` and `import.meta.env.X` read in a parsed file,
 * with the offset of the expression. Strings and comments that merely mention them don't count.
 */
export function envReads(ast: Node): Array<{ name: string; offset: number }> {
  const out: Array<{ name: string; offset: number }> = [];
  walkAst(ast, (n) => {
    // const { NEXT_PUBLIC_X } = process.env
    if (n.type === "VariableDeclarator" && n.id.type === "ObjectPattern" && n.init && isEnvObject(n.init)) {
      for (const prop of n.id.properties) {
        if (prop.type !== "ObjectProperty") continue;
        const key = prop.key.type === "Identifier" ? prop.key.name : prop.key.type === "StringLiteral" ? prop.key.value : null;
        if (key) out.push({ name: key, offset: prop.start ?? 0 });
      }
      return;
    }
    if (n.type !== "MemberExpression" && n.type !== "OptionalMemberExpression") return;
    if (!isEnvObject(n.object)) return;
    const p = n.property;
    const name =
      !n.computed && p.type === "Identifier"
        ? p.name
        : n.computed && p.type === "StringLiteral"
          ? p.value
          : n.computed && p.type === "TemplateLiteral" && p.expressions.length === 0
            ? p.quasis[0]!.value.cooked ?? ""
            : null;
    if (name) out.push({ name, offset: n.start ?? 0 });
  });
  return out;
}
