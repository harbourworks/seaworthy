import type { Node } from "@babel/types";
import type { Confidence } from "../../core/finding.js";
import type { ProjectFiles } from "../../core/project.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, resolveImport } from "../code.js";

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Next.js App Router route handlers and Pages Router API routes. */
export const APP_ROUTE_RE = /(^|\/)app\/(.+\/)?route\.[cm]?[jt]s$/;
export const PAGES_API_RE = /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;

/** Calls that establish who the caller is, by name. Matched against the called function's own name. */
const AUTH_CALL_RE =
  /^(auth|currentUser|getAuth|getSession|getServerSession|getServerAuthSession|getToken|getKindeServerSession|validateRequest|verifyIdToken|verifySessionCookie|verifyToken|verifyJwt|jwtVerify|authenticate|authorize|isAuthenticated|isSignedIn|protect|withApiAuthRequired)$|^(get|require|verify|check|ensure|assert|validate|fetch|load)(Current|Signed|Logged|Authed|Authenticated|Session)?(User|Session|Auth|Admin|Token|Claims|Viewer|Member|Owner|Account|Principal)(OrThrow|OrRedirect)?$/i;
/** Wrappers that put auth in front of a handler: withAuth(handler), auth(handler), protect(handler). */
export const AUTH_WRAPPER_RE = /^(with\w*(Auth|Session|User)\w*|auth|protect(ed)?|requireAuth|authenticated|withApiAuthRequired|authMiddleware)$/i;
/** Checking a shared secret or token by hand counts too. */
const HEADER_CHECK_RE =
  /headers\.get\(\s*["'`](authorization|x-api-key|x-cron-secret|x-webhook-secret|x-admin-token)["'`]|headers\[\s*["'`]authorization["'`]\s*\]|headers\.authorization\b|cookies(\(\))?\.get\(\s*(["'`][^"'`]*(session|token|auth|sid)[^"'`]*["'`]|[\w.]*(AUTH|SESSION|TOKEN|Session|Auth|Token)[\w.]*\s*\))|process\.env\.\w*(SECRET|TOKEN|API_KEY)\w*[^\n;]*(!==?|===?)|(!==?|===?)[^\n;]*process\.env\.\w*(SECRET|TOKEN|API_KEY)/i;
/** Routes that are public by design. Webhooks are checked by signature instead (SW-P01). */
const PUBLIC_PATH_RE =
  /(^|\/)([\w-]*-)?(webhooks?|auth|login|log-in|signin|sign-in|signup|sign-up|register|logout|sign-out|signout|callback|oauth|reset-password|forgot-password|verify-email|confirm|health|healthz|status|ping|og|opengraph-image|sitemap|robots)(-[\w-]*)?(\/|$)|\[\.\.\.(nextauth|auth)\]/i;
/** POSTs that are often meant to be public: contact forms, newsletters, analytics. */
const OPEN_FORM_RE = /(^|\/)(contact|newsletter|subscribe|waitlist|feedback|track|analytics|events|beacon|vitals|log|csp-report)(\/|$)/i;
const CAPTCHA_RE = /recaptcha|turnstile|hcaptcha|captcha/i;
const SETS_AUTH_COOKIE_RE = /cookies\.set\(\s*[\w."'`-]*(auth|session|token)/i;
const SIGNATURE_RE = /constructEvent|stripe-signature|svix|webhook-signature|x-hub-signature|verifySignature|validateSignature/i;

export const a01NoAuthCheck: Rule = {
  id: "SW-A01",
  title: "API route with no auth check",
  severity: "high",
  confidence: "high",
  appliesTo: ["nextjs"],
  docs: {
    summary:
      "API routes and server actions are public URLs: anyone can call them with curl, whatever your UI " +
      "shows. A route that changes data without first checking who is calling lets anyone delete, edit " +
      "or create records, or run up costs on paid APIs. AI tools often add the check to one handler in a " +
      "file and forget it in the next. Webhooks, login routes and health checks are left alone: they are " +
      "public by design.",
    bad: `export async function DELETE(req: Request, { params }) {\n  await db.from("notes").delete().eq("id", params.id);\n}`,
    good:
      `export async function DELETE(req: Request, { params }) {\n  const user = await getUser(req);\n` +
      `  if (!user) return new Response("Unauthorised", { status: 401 });\n` +
      `  await db.from("notes").delete().eq("id", params.id).eq("user_id", user.id);\n}`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    const middleware = loadMiddleware(project);
    for (const file of codeFiles(project)) {
      const appRoute = APP_ROUTE_RE.test(file);
      const pagesApi = PAGES_API_RE.test(file);
      const text = project.read(file);
      if (!text) continue;
      const serverActions = !appRoute && !pagesApi && /^\s*["']use server["']/m.test(text);
      if (!appRoute && !pagesApi && !serverActions) continue;
      const url = routeUrl(file);
      if (url && PUBLIC_PATH_RE.test(url)) continue;
      if (SIGNATURE_RE.test(text)) continue; // a signed webhook: SW-P01's territory
      if (url && middleware.covers(url)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const evidence = new Evidence(project, file, text, ast);

      const all = handlers(ast, appRoute, pagesApi);
      const checked = new Set(
        all.filter((h) => (h.wrapperName && AUTH_WRAPPER_RE.test(h.wrapperName)) || evidence.inFunction(h.fn)),
      );
      for (const h of all) {
        if (checked.has(h)) continue;
        h.siblingChecks = checked.size > 0;
        const fnText = text.slice(h.fn.start ?? 0, h.fn.end ?? 0);
        if (CAPTCHA_RE.test(fnText) || SETS_AUTH_COOKIE_RE.test(fnText)) continue; // public form or login endpoint
        const fnBody = text.slice(h.fn.start ?? 0, h.fn.end ?? 0);
        // High only when the handler does something with consequences: a write method alone
        // (a POST that just computes or returns simulated data) is medium.
        const consequential = looksLikeWrite(fnBody) || consequence(fnBody) !== "";
        const writes = (h.method ? WRITE_METHODS.has(h.method) : true) && consequential;
        let confidence: Confidence = writes ? "high" : "medium";
        const proxies = /\bfetch\(\s*[\w`$.{}/+]*(upstream|backend|api_?url|server_?api|base_?url)/i.test(text.slice(h.fn.start ?? 0, h.fn.end ?? 0)) ||
          /process\.env\.\w*(API_URL|BACKEND|UPSTREAM)\w*/.test(text);
        if (proxies) confidence = "medium";
        if (serverActions || (url && OPEN_FORM_RE.test(url))) confidence = "medium";
        const body = text.slice(h.fn.start ?? 0, h.fn.end ?? 0);
        const label = serverActions ? `Server action ${h.name}` : `${h.method ?? "Handler"} ${url ?? file}`;
        out.push({
          file,
          ...project.position(file, h.at),
          confidence,
          title: `${label} has no auth check`,
          why:
            `${serverActions ? "This server action can be called by anyone, from any page or script" : `Anyone can call ${h.method ?? "this route"} ${url ?? ""}`.trim()}, ` +
            `and nothing in it checks who the caller is.` +
            consequence(body) +
            (h.siblingChecks ? ` Other handlers in this file do check the user, so this one was probably missed.` : ``),
          fix:
            `Check the caller at the top of the handler and stop if there isn't one: ` +
            `\`const user = await getUser(req); if (!user) return new Response("Unauthorised", { status: 401 });\` ` +
            `(or your auth library's equivalent, such as \`auth()\` or \`getServerSession()\`). Then make sure the user ` +
            `may act on this particular record, not just that they're logged in.`,
          fixPrompt:
            `In ${file}, the ${serverActions ? `server action ${h.name}` : `${h.method ?? ""} handler`.trim()} doesn't check who is calling it. ` +
            `Add an authentication check at the top using the same auth approach as the rest of my app, return 401 if ` +
            `there is no signed-in user, and check that the user owns or may modify the records it touches.`,
        });
      }
    }
    return out;
  },
};

export interface Handler {
  name: string;
  method: string | null;
  fn: Node;
  /** Where to report: the export statement. */
  at: number;
  wrapperName: string | null;
  siblingChecks: boolean;
}

export function handlers(ast: Node, appRoute: boolean, pagesApi: boolean): Handler[] {
  const found: Handler[] = [];
  walkAst(ast, (n) => {
    if (n.type === "ExportNamedDeclaration" && n.declaration) {
      const d = n.declaration;
      if (d.type === "FunctionDeclaration" && d.id) {
        found.push({ name: d.id.name, method: methodOf(d.id.name, appRoute), fn: d, at: n.start ?? 0, wrapperName: null, siblingChecks: false });
      } else if (d.type === "VariableDeclaration") {
        for (const v of d.declarations) {
          if (v.id.type !== "Identifier" || !v.init) continue;
          const init = v.init as Node;
          if (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression") {
            found.push({ name: v.id.name, method: methodOf(v.id.name, appRoute), fn: init, at: n.start ?? 0, wrapperName: null, siblingChecks: false });
          } else if (init.type === "CallExpression") {
            const inner = init.arguments.find((a) => a.type === "ArrowFunctionExpression" || a.type === "FunctionExpression");
            const c = init.callee;
            const wrapper = c.type === "Identifier" ? c.name : c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : null;
            if (inner) found.push({ name: v.id.name, method: methodOf(v.id.name, appRoute), fn: inner as Node, at: n.start ?? 0, wrapperName: wrapper, siblingChecks: false });
          }
        }
      }
      return false;
    }
    if (pagesApi && n.type === "ExportDefaultDeclaration") {
      const d = n.declaration as Node;
      if (d.type === "FunctionDeclaration" || d.type === "ArrowFunctionExpression" || d.type === "FunctionExpression") {
        found.push({ name: "default", method: null, fn: d, at: n.start ?? 0, wrapperName: null, siblingChecks: false });
      } else if (d.type === "CallExpression") {
        const inner = d.arguments.find((a) => a.type === "ArrowFunctionExpression" || a.type === "FunctionExpression");
        const wrapper = d.callee.type === "Identifier" ? d.callee.name : null;
        if (inner) found.push({ name: "default", method: null, fn: inner as Node, at: n.start ?? 0, wrapperName: wrapper, siblingChecks: false });
      }
      return false;
    }
  });
  // In a route file, only HTTP method exports are handlers.
  return appRoute ? found.filter((h) => h.method !== null) : found;
}

function methodOf(name: string, appRoute: boolean): string | null {
  return appRoute && HTTP_METHODS.has(name) ? name : null;
}

/** Whether a function, or a helper it calls, checks who the caller is. */
export class Evidence {
  private localFns = new Map<string, Node>();
  private imported = new Map<string, string>(); // local name -> module specifier
  private cache = new Map<Node, boolean>();

  constructor(
    private project: ProjectFiles,
    private file: string,
    private text: string,
    ast: Node,
  ) {
    walkAst(ast, (n) => {
      if (n.type === "FunctionDeclaration" && n.id) this.localFns.set(n.id.name, n);
      if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init &&
          (n.init.type === "ArrowFunctionExpression" || n.init.type === "FunctionExpression")) this.localFns.set(n.id.name, n.init);
      if (n.type === "ImportDeclaration") {
        for (const s of n.specifiers) this.imported.set(s.local.name, n.source.value);
      }
    });
  }

  inFunction(fn: Node, depth = 0): boolean {
    if (this.cache.has(fn)) return this.cache.get(fn)!;
    this.cache.set(fn, false); // guards against recursion
    const body = this.text.slice(fn.start ?? 0, fn.end ?? 0);
    let found = HEADER_CHECK_RE.test(body);
    if (!found) {
      walkAst(fn, (n) => {
        if (found) return false;
        if (n.type !== "CallExpression") return;
        const c = n.callee;
        const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : null;
        if (!name) return;
        if (AUTH_CALL_RE.test(name)) {
          found = true;
          return false;
        }
        if (depth >= 2 || c.type !== "Identifier") return;
        // A helper defined in this file, or imported from a local file, that checks auth.
        const local = this.localFns.get(name);
        if (local && local !== fn && this.inFunction(local, depth + 1)) found = true;
        const spec = this.imported.get(name);
        if (!found && spec) {
          const target = resolveImport(this.project, this.file, spec);
          const t = target ? this.project.read(target) : null;
          if (t && helperChecksAuth(t, name)) found = true;
        }
      });
    }
    this.cache.set(fn, found);
    return found;
  }
}

/** In an imported module, does the named function check auth? Text-level, scoped to that function where possible. */
function helperChecksAuth(moduleText: string, name: string): boolean {
  const start = moduleText.search(new RegExp(`(function\\s+${name}\\b|\\b${name}\\s*=\\s*(async\\s*)?(\\(|function))`));
  const body = start >= 0 ? moduleText.slice(start, start + 4000) : moduleText;
  if (HEADER_CHECK_RE.test(body)) return true;
  for (const m of body.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) if (m[1] !== name && AUTH_CALL_RE.test(m[1]!)) return true;
  return /\.auth\.(getUser|getSession)\s*\(|\bverifyIdToken\s*\(|\bjwt\.verify\s*\(/.test(body);
}

function looksLikeWrite(body: string): boolean {
  return /\.(insert|update|upsert|delete|remove|create|createMany|destroy|save|put|set)\s*\(|\bexec(Sync)?\s*\(|\bspawn\s*\(|req\.method\s*===?\s*["'](POST|PUT|PATCH|DELETE)["']/.test(body);
}

/** What the handler can do, for the "why". */
function consequence(body: string): string {
  if (/\b(exec|execSync|spawn|run)\s*\(/.test(body) && /tool_calls|function\.arguments|run_shell|command/.test(body)) {
    return " It also runs shell commands chosen by a model, so anyone can run commands on your server.";
  }
  if (/supabaseAdmin|service_role|SERVICE_ROLE/.test(body)) return " It uses the admin database client, which bypasses row-level security.";
  if (/\.(delete|destroy|remove)\s*\(/.test(body)) return " It deletes data, so anyone can delete records.";
  if (/\b(openai|anthropic|completions\.create|messages\.create|generateText|streamText)\b/.test(body)) {
    return " It calls a paid AI model, so anyone can run up your bill.";
  }
  if (/\.(insert|update|upsert|create|save)\s*\(/.test(body)) return " It writes to your database.";
  return "";
}

/** The URL a route file serves, such as /api/notes/[id]. Route groups like (admin) are dropped. */
export function routeUrl(file: string): string | null {
  let m = /(?:^|\/)app\/(.*?)\/?route\.[cm]?[jt]s$/.exec(file);
  if (m) return "/" + m[1]!.split("/").filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith("@")).join("/");
  m = /(?:^|\/)pages\/(api\/.+?)(\/index)?\.[cm]?[jt]sx?$/.exec(file);
  return m ? "/" + m[1] : null;
}

/** Next.js middleware that enforces auth, and which paths it runs on. */
function loadMiddleware(project: ProjectFiles): { covers(url: string): boolean } {
  const none = { covers: () => false };
  const file = project.files.find((f) => /^(src\/)?middleware\.[cm]?[jt]s$/.test(f));
  const text = file ? project.read(file) : null;
  if (!text) return none;
  // It must actually turn people away, not just refresh a session.
  const enforces =
    /\.protect\s*\(|redirect\s*\(|status:\s*401|Unauthori[sz]ed|withAuth|next-auth\/middleware|authMiddleware|signIn/.test(text);
  if (!enforces) return none;
  const matcherBlock = /matcher\s*:\s*(\[[\s\S]*?\]|["'`][^"'`]*["'`])/.exec(text)?.[1];
  if (!matcherBlock) return { covers: () => true }; // no matcher: runs on every path
  const patterns = [...matcherBlock.matchAll(/["'`]([^"'`]+)["'`]/g)].map((m) => m[1]!);
  const regexes = patterns.map((p) => {
    try {
      if (p.includes("(")) return new RegExp(`^${p}$`); // already a regex, e.g. "/((?!_next/static).*)"
      const re = p.replace(/[.+?^${}|[\]\\]/g, "\\$&").replace(/\/:\w+\*/g, "(/.*)?").replace(/:\w+\+/g, ".+").replace(/:\w+/g, "[^/]+");
      return new RegExp(`^${re}$`);
    } catch {
      return null;
    }
  });
  return { covers: (url) => regexes.some((r) => r?.test(url.replace(/\[[^\]]+\]/g, "x"))) };
}
