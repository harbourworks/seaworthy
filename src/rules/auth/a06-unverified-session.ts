import type { Node } from "@babel/types";
import type { ProjectFiles } from "../../core/project.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, isClientFile, resolveImport } from "../code.js";
import { APP_ROUTE_RE, PAGES_API_RE, routeUrl } from "./a01-no-auth-check.js";

/** Next.js middleware (or `proxy.ts`, its Next.js 16 name), at the project root or in src/. */
const MIDDLEWARE_RE = /^(src\/)?(middleware|proxy)\.[cm]?[jt]s$/;
/** App Router files that render as server components unless marked "use client". */
const SERVER_COMPONENT_RE = /(^|\/)app\/(.+\/)?(page|layout|template|default|not-found)\.[cm]?[jt]sx?$/;
const TEST_FILE_RE = /\.(test|spec)\.[cm]?[jt]sx?$/;
/** A verified check in a helper's source: getUser() asks Supabase Auth, getClaims() checks the token's signature. */
const VERIFY_TEXT_RE = /\.auth\s*\.\s*(getUser|getClaims)\s*\(/;
/** Calls that turn the caller away. */
const EXIT_CALL_RE = /^(redirect|permanentRedirect|notFound|unauthorized|forbidden)$/;
/** Query-builder and ORM methods: a user ID passed to one of these is used as an owner. */
const QUERY_METHOD_RE =
  /^(eq|neq|match|filter|in|is|contains|or|insert|update|upsert|delete|where|values|set|findMany|findFirst|findFirstOrThrow|findUnique|findUniqueOrThrow|create|createMany|updateMany|deleteMany|count|aggregate)$/;

type Kind = "route" | "pages" | "action" | "component" | "middleware";

export const a06UnverifiedSession: Rule = {
  id: "SW-A06",
  title: "Server-side auth decision trusts an unverified Supabase session",
  severity: "high",
  confidence: "medium",
  appliesTo: ["supabase"],
  docs: {
    summary:
      "On the server, `supabase.auth.getSession()` reads the session from the request's cookies without " +
      "verifying it, so its contents may not be authentic. Supabase's docs say never to trust it in server " +
      "code, and to protect pages and data with `getClaims()`, which verifies the token's signature, or " +
      "`getUser()`, which asks Supabase Auth. A route, page, server action or middleware that lets people in " +
      "because `getSession()` returned a session, or takes the user ID for a query from it, can be fooled by a " +
      "made-up or tampered cookie. The `getSession()` version is the shortest guard to write, and many older " +
      "tutorials use it.",
    bad:
      `const { data: { session } } = await supabase.auth.getSession();\n` +
      `if (!session) return new Response("Unauthorized", { status: 401 });\n` +
      `await supabase.from("invoices").select("*").eq("user_id", session.user.id);`,
    good:
      `const { data: { user } } = await supabase.auth.getUser();\n` +
      `if (!user) return new Response("Unauthorized", { status: 401 });\n` +
      `await supabase.from("invoices").select("*").eq("user_id", user.id);`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      if (TEST_FILE_RE.test(file)) continue;
      const text = project.read(file);
      if (!text || !/\bgetSession\b/.test(text) || isClientFile(text)) continue;
      const kind = kindOf(file, text);
      if (!kind) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      out.push(...checkFile(project, file, text, ast, kind));
    }
    return out;
  },
};

/** The kind of server code a file holds, or null for files this rule doesn't read. */
function kindOf(file: string, text: string): Kind | null {
  if (MIDDLEWARE_RE.test(file)) return "middleware";
  if (APP_ROUTE_RE.test(file)) return "route";
  if (PAGES_API_RE.test(file)) return "pages";
  if (SERVER_COMPONENT_RE.test(file)) return "component";
  return /^\s*["']use server["']/m.test(text) ? "action" : null;
}

function checkFile(project: ProjectFiles, file: string, text: string, ast: Node, kind: Kind): RawFinding[] {
  const parents = new Map<Node, Node | null>();
  const sessionCalls: Node[] = [];
  const localFns = new Map<string, Node>();
  const imported = new Map<string, string>();
  walkAst(ast, (n, parent) => {
    parents.set(n, parent);
    if (n.type === "CallExpression" && authMethod(n) === "getSession") sessionCalls.push(n);
    if (n.type === "FunctionDeclaration" && n.id) localFns.set(n.id.name, n);
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init &&
        (n.init.type === "ArrowFunctionExpression" || n.init.type === "FunctionExpression")) localFns.set(n.id.name, n.init);
    if (n.type === "ImportDeclaration") for (const s of n.specifiers) imported.set(s.local.name, n.source.value);
  });
  if (sessionCalls.length === 0) return [];

  /** Whether code calls getUser() or getClaims(), itself or through a helper in this file or a local import. */
  const verifies = (scope: Node, depth = 0): boolean => {
    let found = false;
    walkAst(scope, (n) => {
      if (found) return false;
      if (n.type !== "CallExpression") return;
      const m = authMethod(n);
      if (m === "getUser" || m === "getClaims") return void (found = true);
      if (n.callee.type !== "Identifier" || depth >= 2) return;
      const name = n.callee.name;
      const local = localFns.get(name);
      if (local && local !== scope && verifies(local, depth + 1)) return void (found = true);
      const spec = imported.get(name);
      const target = spec ? resolveImport(project, file, spec) : null;
      const t = target ? project.read(target) : null;
      if (t && helperVerifies(t, name)) found = true;
    });
    return found;
  };

  const out: RawFinding[] = [];
  for (const call of sessionCalls) {
    // The handler, page, action or middleware function that makes the call: its outermost function.
    let fn: Node | null = null;
    for (let p = parents.get(call); p; p = parents.get(p) ?? null) if (isFunction(p)) fn = p;
    if (!fn) continue;
    const scope = kind === "middleware" ? ast : fn;
    if (verifies(scope)) continue;
    const use = howUsed(text, call, fn, parents);
    if (!use.guard && !use.owner) continue;

    const name = functionName(fn, parents);
    const url = routeUrl(file);
    let label: string;
    let subject: string;
    if (kind === "route") {
      label = `${name ?? "Handler"} ${url}`;
      subject = name ? `the ${name} handler` : "the route handler";
    } else if (kind === "pages") {
      label = `Handler ${url}`;
      subject = "the API handler";
    } else if (kind === "action") {
      label = `Server action ${name ?? "default"}`;
      subject = `the server action ${name ?? "default"}`;
    } else if (kind === "component") {
      const what = /\/layout\.[^/]+$/.test(file) ? "Layout" : /\/template\.[^/]+$/.test(file) ? "Template" : "Page";
      label = `${what} ${pagePath(file)}`;
      subject = `the ${what.toLowerCase()} component`;
    } else {
      label = /(^|\/)proxy\.[^/]+$/.test(file) ? "Proxy" : "Middleware";
      subject = label === "Proxy" ? "the proxy" : "the middleware";
    }
    const what = use.guard && use.owner ? "sign-in and the user ID" : use.guard ? "sign-in" : "the user ID";
    const does =
      use.guard && use.owner
        ? `uses that session to decide whether the caller is signed in, and passes its user ID (\`${use.owner}\`) to a query as the owner`
        : use.guard
          ? "uses that session to decide whether the caller is signed in"
          : `passes the user ID from that session (\`${use.owner}\`) to a query as the owner`;
    const gets = use.guard && use.owner ? "get past this check and choose that user ID" : use.guard ? "get past this check" : "choose that user ID";
    const where = kind === "middleware" ? "this file" : "this function";
    out.push({
      file,
      ...project.position(file, call.start ?? 0),
      title: `${label} trusts an unverified Supabase session for ${what}`,
      why:
        `\`auth.getSession()\` reads the session from the request's cookies without verifying it, so the session ` +
        `and the user in it may not be authentic. This code ${does}. Nothing in ${where} calls ` +
        `\`auth.getUser()\` or \`auth.getClaims()\`. A made-up or tampered session cookie can ${gets}. ` +
        `Supabase's docs say never to trust \`getSession()\` in server code.`,
      fix:
        `Check the user with \`supabase.auth.getClaims()\`, which verifies the token's signature (against your ` +
        `project's public keys, or by asking Supabase Auth if the project still uses a shared secret), or with ` +
        `\`supabase.auth.getUser()\` if you need the full user record, which asks Supabase Auth. Use that result for ` +
        `the signed-in check and the user ID (\`data.claims.sub\` or \`user.id\`). Keep \`getSession()\` only for ` +
        `client-side UI, or for reading the access token after one of those checks has passed.`,
      fixPrompt:
        `In ${file}, ${subject} calls supabase.auth.getSession() on the server and uses its result ` +
        `${use.guard && use.owner ? "to decide whether the user is signed in and as the user ID in a query" : use.guard ? "to decide whether the user is signed in" : "as the user ID in a query"}. ` +
        `getSession() reads the session from the cookies without verifying it. Replace it with supabase.auth.getClaims() ` +
        `(or supabase.auth.getUser() if you need the full user record), and use that result for the signed-in check ` +
        `and the user ID (data.claims.sub or user.id). Keep getSession() only for client-side UI, or for reading the ` +
        `access token after the getClaims() or getUser() check has passed.`,
    });
  }
  return out;
}

/** `x.auth.getSession()`, `auth.getUser()` and the like: the method name, when it is called on `auth`. */
function authMethod(call: Node): string | null {
  if (call.type !== "CallExpression") return null;
  const c = call.callee;
  if ((c.type !== "MemberExpression" && c.type !== "OptionalMemberExpression") || c.computed || c.property.type !== "Identifier") return null;
  const o = c.object;
  const onAuth =
    (o.type === "Identifier" && o.name === "auth") ||
    ((o.type === "MemberExpression" || o.type === "OptionalMemberExpression") && !o.computed &&
      o.property.type === "Identifier" && o.property.name === "auth");
  return onAuth ? c.property.name : null;
}

function isFunction(n: Node): boolean {
  return n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" ||
    n.type === "ObjectMethod" || n.type === "ClassMethod";
}

function functionName(fn: Node, parents: Map<Node, Node | null>): string | null {
  if (fn.type === "FunctionDeclaration" && fn.id) return fn.id.name;
  const p = parents.get(fn);
  if (p?.type === "VariableDeclarator" && p.id.type === "Identifier") return p.id.name;
  if (p?.type === "ExportDefaultDeclaration") return "default";
  return null;
}

/** In an imported module, does the named function call getUser() or getClaims()? Text-level, as SW-A01 reads helpers. */
function helperVerifies(moduleText: string, name: string): boolean {
  const start = moduleText.search(new RegExp(`(function\\s+${name}\\b|\\b${name}\\s*=\\s*(async\\s*)?(\\(|function|[A-Za-z_$]))`));
  return VERIFY_TEXT_RE.test(start >= 0 ? moduleText.slice(start, start + 4000) : moduleText);
}

/** The path a page serves, such as /dashboard. Route groups like (admin) are dropped. */
function pagePath(file: string): string {
  const m = /(?:^|\/)app\/(.*?)\/?[^/]+$/.exec(file);
  return "/" + (m?.[1] ?? "").split("/").filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith("@")).join("/");
}

/**
 * How the result of a getSession() call is used in its function: as a guard (an `if`, `?:`, `&&` or `||` on it
 * that returns, throws or redirects, unless that exit is only a redirect taken when a session is present, as when a
 * login page sends signed-in users on), or as the owner ID in a query (`<session>.user.id` passed to a query
 * method). Follows the variables it is destructured or copied into.
 */
function howUsed(text: string, call: Node, fn: Node, parents: Map<Node, Node | null>): { guard: boolean; owner: string | null } {
  /** Variable name -> the path from getSession()'s result to its value, such as ["data", "session"]. */
  const vars = new Map<string, string[]>();
  const bind = (pattern: Node, path: string[]) => {
    if (pattern.type === "Identifier") {
      if (!path.includes("error")) vars.set(pattern.name, path);
    } else if (pattern.type === "ObjectPattern") {
      for (const p of pattern.properties) {
        if (p.type === "RestElement") bind(p.argument, path);
        else if (!p.computed && (p.key.type === "Identifier" || p.key.type === "StringLiteral")) {
          bind(p.value as Node, [...path, p.key.type === "Identifier" ? p.key.name : p.key.value]);
        }
      }
    } else if (pattern.type === "AssignmentPattern") bind(pattern.left, path);
  };

  // The declaration that receives the call's result: `const { data } = await x.auth.getSession()`,
  // `const s = (await x.auth.getSession()).data.session`, `const s = await x.auth.getSession().then((r) => r.data.session)`.
  let node: Node = call;
  const path: string[] = [];
  for (let p = parents.get(node); p; node = p, p = parents.get(p) ?? null) {
    if (p.type === "AwaitExpression" || p.type === "TSNonNullExpression" || p.type === "ParenthesizedExpression") continue;
    if ((p.type === "MemberExpression" || p.type === "OptionalMemberExpression") && p.object === node && !p.computed && p.property.type === "Identifier") {
      const then = p.property.name === "then" ? parents.get(p) : null;
      if (then?.type === "CallExpression" && then.callee === p) {
        const props = thenPath(then.arguments[0] as Node | undefined);
        if (!props) break;
        path.push(...props);
        p = then; // carry on from the .then(...) call
        continue;
      }
      path.push(p.property.name);
      continue;
    }
    if (p.type === "VariableDeclarator" && p.init === node) bind(p.id, path);
    break;
  }
  if (vars.size === 0) return { guard: false, owner: null };

  /** For a reference to a tracked variable: its full path from the session result, and the outermost expression. */
  const resolve = (id: Node): { path: string[]; top: Node } | null => {
    if (id.type !== "Identifier" || !vars.has(id.name)) return null;
    const parent = parents.get(id);
    if (!parent) return null;
    if ((parent.type === "MemberExpression" || parent.type === "OptionalMemberExpression") && parent.property === id && !parent.computed) return null;
    if ((parent.type === "ObjectProperty") && parent.key === id && !parent.shorthand) return null;
    if (parent.type === "VariableDeclarator" && parent.id === id) return null;
    const full = [...vars.get(id.name)!];
    let top: Node = id;
    for (let p = parents.get(top); p; top = p, p = parents.get(p) ?? null) {
      if (p.type === "TSNonNullExpression" || p.type === "ParenthesizedExpression") continue;
      if ((p.type === "MemberExpression" || p.type === "OptionalMemberExpression") && p.object === top && !p.computed && p.property.type === "Identifier") {
        full.push(p.property.name);
        continue;
      }
      break;
    }
    return { path: full, top };
  };

  // Copies: `const user = session.user`, `const { user } = data.session`, `const uid = session?.user.id`.
  for (let round = 0; round < 3; round++) {
    const before = vars.size;
    walkAst(fn, (n) => {
      if (n.type !== "VariableDeclarator" || !n.init) return;
      let init: Node = n.init;
      while (init.type === "TSNonNullExpression" || init.type === "ParenthesizedExpression") init = init.expression;
      const root = rootIdentifier(init);
      const r = root ? resolve(root) : null;
      if (r && (r.top === init || r.top === n.init)) bind(n.id, r.path);
    });
    if (vars.size === before) break;
  }

  let guard = false;
  let owner: string | null = null;
  const mentions = (n: Node | null | undefined): boolean => {
    if (!n) return false;
    let hit = false;
    walkAst(n, (x) => {
      if (hit) return false;
      if (x.type === "Identifier" && resolve(x)) hit = true;
    });
    return hit;
  };
  const exits = (n: Node | null | undefined): boolean => {
    if (!n) return false;
    let hit = false;
    walkAst(n, (x) => {
      if (hit || (x !== n && isFunction(x))) return false;
      if (x.type === "ReturnStatement" || x.type === "ThrowStatement") hit = true;
      if (x.type === "CallExpression") {
        const c = x.callee;
        const name = c.type === "Identifier" ? c.name : (c.type === "MemberExpression" && c.property.type === "Identifier") ? c.property.name : null;
        if (name && EXIT_CALL_RE.test(name)) hit = true;
      }
    });
    return hit;
  };

  /** Whether a tracked value is known to be there ("present") or missing ("absent") when `test` is `outcome`. */
  const side = (test: Node, outcome: boolean): "present" | "absent" | null => {
    let t: Node = test;
    while (t.type === "TSNonNullExpression" || t.type === "ParenthesizedExpression") t = t.expression;
    if (t.type === "UnaryExpression" && t.operator === "!") return side(t.argument, !outcome);
    if (t.type === "LogicalExpression" && t.operator !== "??") {
      // `a && b` is true only when both are; `a || b` is false only when both are. Otherwise either side could decide.
      if ((t.operator === "&&") === outcome) return side(t.left, outcome) ?? side(t.right, outcome);
      const l = side(t.left, outcome);
      return l !== null && l === side(t.right, outcome) ? l : null;
    }
    if (t.type === "BinaryExpression" && ["==", "===", "!=", "!=="].includes(t.operator)) {
      const empty = (x: Node) => x.type === "NullLiteral" || (x.type === "Identifier" && x.name === "undefined");
      const other = empty(t.right) ? t.left : empty(t.left) ? t.right : null;
      if (!other || other.type === "PrivateName") return null;
      if (side(other, true) === null) return null; // not a tracked value
      // `session === null` is true when there's no session; `session !== null` when there is one.
      const equal = t.operator === "==" || t.operator === "===";
      return equal === outcome ? "absent" : "present";
    }
    const root = rootIdentifier(t);
    const r = root ? resolve(root) : null;
    return r && r.top === t ? (outcome ? "present" : "absent") : null;
  };
  /** An exit on the signed-in side that only redirects, such as sending a signed-in user away from /login: no guard. */
  const signedInRedirect = (branch: Node | null | undefined, when: "present" | "absent" | null): boolean =>
    when === "present" && !!branch && redirectsOnly(branch);
  const guards = (branch: Node | null | undefined, when: "present" | "absent" | null): boolean =>
    exits(branch) && !signedInRedirect(branch, when);

  walkAst(fn, (n) => {
    if ((n.type === "IfStatement" || n.type === "ConditionalExpression") && mentions(n.test) &&
        (guards(n.consequent, side(n.test, true)) || guards(n.alternate, side(n.test, false)))) guard = true;
    if (n.type === "LogicalExpression" && mentions(n.left) && guards(n.right, side(n.left, n.operator === "&&"))) guard = true;
    if (!owner && n.type === "Identifier") {
      const r = resolve(n);
      if (r && r.path.slice(-2).join(".") === "user.id" && inQuery(r.top, parents)) {
        owner = text.slice(r.top.start ?? 0, r.top.end ?? 0).replace(/\s+/g, "").replace(/[?!]/g, "");
      }
    }
  });
  return { guard, owner };
}

/** Whether every way a branch exits is a redirect: `redirect(...)`, `permanentRedirect(...)` or a returned `NextResponse.redirect(...)`. */
function redirectsOnly(branch: Node): boolean {
  let ok = true;
  let any = false;
  const isRedirect = (x: Node | null | undefined): boolean => {
    while (x && (x.type === "AwaitExpression" || x.type === "TSNonNullExpression" || x.type === "ParenthesizedExpression")) x = x.type === "AwaitExpression" ? x.argument : x.expression;
    if (!x || x.type !== "CallExpression") return false;
    const c = x.callee;
    const name = c.type === "Identifier" ? c.name : (c.type === "MemberExpression" && c.property.type === "Identifier") ? c.property.name : null;
    return name === "redirect" || name === "permanentRedirect";
  };
  walkAst(branch, (x) => {
    if (!ok || (x !== branch && isFunction(x))) return false;
    if (x.type === "ThrowStatement") ok = false;
    if (x.type === "ReturnStatement") {
      any = true;
      if (!isRedirect(x.argument)) ok = false;
    }
    if (x.type === "CallExpression") {
      const c = x.callee;
      const name = c.type === "Identifier" ? c.name : (c.type === "MemberExpression" && c.property.type === "Identifier") ? c.property.name : null;
      if (name && EXIT_CALL_RE.test(name)) {
        any = true;
        if (!isRedirect(x)) ok = false;
      }
    }
  });
  return ok && any;
}

/** For `.then((r) => r.data.session)`: the path the callback reads from its argument, here ["data", "session"]. */
function thenPath(cb: Node | undefined): string[] | null {
  if (!cb || cb.type !== "ArrowFunctionExpression" || cb.params.length !== 1 || cb.params[0]!.type !== "Identifier") return null;
  const param = cb.params[0]!.name;
  const props: string[] = [];
  let x: Node = cb.body;
  while (x.type === "MemberExpression" || x.type === "OptionalMemberExpression" || x.type === "TSNonNullExpression") {
    if (x.type === "TSNonNullExpression") x = x.expression;
    else if (x.computed || x.property.type !== "Identifier") return null;
    else {
      props.unshift(x.property.name);
      x = x.object;
    }
  }
  return x.type === "Identifier" && x.name === param ? props : null;
}

function rootIdentifier(n: Node): Node | null {
  let x: Node = n;
  while (x.type === "MemberExpression" || x.type === "OptionalMemberExpression" || x.type === "TSNonNullExpression") {
    x = x.type === "TSNonNullExpression" ? x.expression : x.object;
  }
  return x.type === "Identifier" ? x : null;
}

/** Whether an expression is an argument (directly, or inside an object or array) to a query method. */
function inQuery(expr: Node, parents: Map<Node, Node | null>): boolean {
  let node = expr;
  for (let p = parents.get(node); p; node = p, p = parents.get(p) ?? null) {
    if (p.type === "CallExpression" || p.type === "OptionalCallExpression") {
      if (p.callee === node) return false;
      const c = p.callee;
      if ((c.type === "MemberExpression" || c.type === "OptionalMemberExpression") && c.property.type === "Identifier" && QUERY_METHOD_RE.test(c.property.name)) return true;
      continue; // a helper call such as drizzle's eq(...), inside .where(...)
    }
    if (p.type === "ObjectProperty" || p.type === "ObjectExpression" || p.type === "ArrayExpression" ||
        p.type === "TSNonNullExpression" || p.type === "TSAsExpression" || p.type === "ParenthesizedExpression" ||
        p.type === "SpreadElement" || p.type === "TemplateLiteral" || p.type === "LogicalExpression") continue;
    return false;
  }
  return false;
}
