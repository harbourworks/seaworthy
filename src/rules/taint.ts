/**
 * A small, file-local data-flow check: which variables hold values that came from a
 * source (request input, model output). It follows declarations, destructuring, simple
 * reassignment through other variables, React state setters and `.map` callbacks. It is
 * deliberately conservative: a value passed through a sanitiser stops being tainted, and
 * passing a source to an arbitrary function (`getUser(req)`) does not taint the result
 * unless the expression itself matches the source pattern.
 */
import type { Node } from "@babel/types";
import { walkAst } from "../core/js.js";

export interface TaintOptions {
  /** Matched against an expression's source text. */
  source: RegExp;
  /** Expressions matching this are clean, whatever they contain. */
  sanitiser?: RegExp;
  /** Treat every parameter of every function as tainted (server actions). */
  allParams?: boolean;
  /** Treat a destructured `{ params }` function parameter as tainted (route handlers). */
  routeParams?: boolean;
}

export interface Taint {
  isTainted(expr: Node): boolean;
  /** Variables that hold a string built with `+` or an untagged template, by name. */
  builders: Map<string, Node>;
}

export const SANITISER_RE = /\b(DOMPurify|purify|sanitize|sanitise|sanitizeHtml|xss|escapeHtml|escape)\b/;

export function analyseTaint(ast: Node, text: string, opts: TaintOptions): Taint {
  const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);
  const tainted = new Set<string>();
  const builders = new Map<string, Node>();
  /** name := expr edges: declarations, assignments and state setter calls. */
  const flows: Array<{ names: string[]; from: Node }> = [];
  const setters = new Map<string, string>(); // setReply -> reply
  const mapCallbacks: Array<{ over: Node; params: string[] }> = [];

  walkAst(ast, (n) => {
    if (n.type === "VariableDeclarator" && n.init) {
      const id = n.id as Node;
      // const [reply, setReply] = useState(...)
      if (id.type === "ArrayPattern" && n.init.type === "CallExpression" && /^(useState|useReducer)$/.test(calleeName(n.init) ?? "")) {
        const [value, setter] = id.elements;
        if (value?.type === "Identifier" && setter?.type === "Identifier") setters.set(setter.name, value.name);
      }
      flows.push({ names: patternNames(id), from: n.init });
      if (id.type === "Identifier" && buildsString(n.init)) builders.set(id.name, n.init);
    }
    if (n.type === "AssignmentExpression" && n.left.type === "Identifier") {
      flows.push({ names: [n.left.name], from: n.right });
    }
    if (n.type === "FunctionDeclaration" || n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression") {
      const params = n.params as Node[];
      if (opts.allParams) for (const p of params) for (const x of patternNames(p)) tainted.add(x);
      if (opts.routeParams) {
        for (const p of params) if (p.type === "ObjectPattern" && patternNames(p).includes("params")) tainted.add("params");
      }
    }
    if (n.type === "CallExpression") {
      // setReply(expr) flows into reply.
      const name = calleeName(n);
      if (name && n.arguments[0]) flows.push({ names: [`setter:${name}`], from: n.arguments[0] as Node });
      // tainted.map((m) => ...) taints m.
      const c = n.callee;
      const fn = n.arguments[0];
      if (
        c.type === "MemberExpression" &&
        c.property.type === "Identifier" &&
        /^(map|forEach|filter|flatMap|find|some|every|reduce)$/.test(c.property.name) &&
        fn &&
        (fn.type === "ArrowFunctionExpression" || fn.type === "FunctionExpression")
      ) {
        const first = fn.params[c.property.name === "reduce" ? 1 : 0];
        if (first) mapCallbacks.push({ over: c.object as Node, params: patternNames(first as Node) });
      }
    }
  });

  const exprTainted = (e: Node): boolean => {
    const s = src(e);
    if (opts.sanitiser?.test(s)) return false;
    if (opts.source.test(s)) return true;
    let hit = false;
    walkAst(e, (x) => {
      if (hit) return false;
      if (x.type === "Identifier" && tainted.has(x.name)) hit = true;
      // A sanitiser call inside the expression cleans what it wraps.
      if (x.type === "CallExpression" && opts.sanitiser?.test(calleeText(x, src))) return false;
    });
    return hit;
  };

  for (let changed = true; changed; ) {
    changed = false;
    for (const f of flows) {
      const names = f.names.map((x) => (x.startsWith("setter:") ? setters.get(x.slice(7)) : x)).filter((x): x is string => !!x);
      if (names.length === 0 || names.every((x) => tainted.has(x))) continue;
      if (exprTainted(f.from)) {
        for (const x of names) tainted.add(x);
        changed = true;
      }
    }
    for (const m of mapCallbacks) {
      if (m.params.every((x) => tainted.has(x)) || !exprTainted(m.over)) continue;
      for (const x of m.params) tainted.add(x);
      changed = true;
    }
  }
  return { isTainted: exprTainted, builders };
}

function calleeName(n: Node): string | null {
  if (n.type !== "CallExpression") return null;
  return n.callee.type === "Identifier" ? n.callee.name : null;
}

function calleeText(n: Node, src: (n: Node) => string): string {
  return n.type === "CallExpression" ? src(n.callee as Node) : "";
}

/** True for a string built with `+` or an untagged template literal with insertions. */
export function buildsString(n: Node): boolean {
  return stringParts(n) !== null;
}

/** Literal text and inserted expressions of a string built with `+` or an untagged template. */
export function stringParts(n: Node): { literal: string; exprs: Node[] } | null {
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

export function patternNames(p: Node): string[] {
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

/** Request input. Passing `req` to a function (`getUser(req)`) does not count. */
export const REQUEST_INPUT_RE =
  /\bsearchParams\b|\b(req|request)\.(query|body|params|cookies)\b|\b(req|request)\.(json|formData|text)\s*\(|\.headers\.get\s*\(|\bformData\.get\s*\(|\bcookies\(\)\.get\s*\(|\buseSearchParams\b/;

/** Model output from the common SDKs. */
export const MODEL_OUTPUT_RE =
  /\.choices\s*\[|\.choices\s*\?\.\s*\[|\bmessage\.content\b|\.output_text\b|\.content\s*\[\s*0\s*\]\s*\.text\b|\bfunction\.arguments\b|\.tool_calls\b|\b(generateText|streamText|generateObject|useChat|useCompletion)\s*\(/;
