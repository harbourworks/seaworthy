import type { Node } from "@babel/types";
import type { Confidence } from "../../core/finding.js";
import type { ProjectFiles } from "../../core/project.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, resolveImport } from "../code.js";
import { REQUEST_INPUT_RE, analyseTaint } from "../taint.js";
import { APP_ROUTE_RE, AUTH_WRAPPER_RE, Evidence, PAGES_API_RE, handlers, routeUrl } from "./a01-no-auth-check.js";

/** Columns that tie a row to a user or a tenant. Filtering or comparing on one counts as an ownership check. */
const OWNER_COL_RE =
  /\b(user_?id|owner_?id|author_?id|creator_?id|created_?by|profile_?id|account_?id|member_?id|customer_?id|org(anization|anisation)?_?id|team_?id|workspace_?id|tenant_?id|company_?id)\b/i;
/** The signed-in user's identity, however it was named. */
const IDENTITY_RE = /\b(user|session\.user|currentUser|me|viewer|claims|token|decoded|authUser)\??\.(id|uid|sub|userId|user_id)\b|\b(userId|uid|currentUserId)\b/;
/** Filter columns that pick out one record by its ID. */
const ID_COL_RE = /^(id|uuid|slug|key|[a-z]+_?id|[a-z]+Id)$/i;
const PRISMA_ONE = /^(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|update|delete|upsert)$/;

export const a02NoOwnershipCheck: Rule = {
  id: "SW-A02",
  title: "Record fetched by ID with no ownership check",
  severity: "high",
  confidence: "high",
  appliesTo: ["nextjs"],
  docs: {
    summary:
      "Checking that someone is logged in is not the same as checking the record is theirs. A route that " +
      "loads, edits or deletes a record by the ID in the URL lets any signed-in user reach anyone's data by " +
      "changing the number (an IDOR). This matters most with database access that skips row-level " +
      "security: the Supabase service-role client, Prisma and Drizzle. With the normal Supabase client, " +
      "row-level security does this job (see SW-D01 and SW-D02).",
    bad: `const user = await getUser(req);\nif (!user) return unauthorised();\nconst { data } = await supabaseAdmin.from("notes").select().eq("id", params.id).single();`,
    good: `const { data } = await supabaseAdmin.from("notes").select()\n  .eq("id", params.id)\n  .eq("user_id", user.id)\n  .single();`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const appRoute = APP_ROUTE_RE.test(file);
      const pagesApi = PAGES_API_RE.test(file);
      const text = project.read(file);
      if (!text) continue;
      const serverActions = !appRoute && !pagesApi && /^\s*["']use server["']/m.test(text);
      if (!appRoute && !pagesApi && !serverActions) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const evidence = new Evidence(project, file, text, ast);
      const { isTainted } = analyseTaint(ast, text, { source: REQUEST_INPUT_RE, routeParams: true, allParams: serverActions });
      const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);
      const url = routeUrl(file);

      for (const h of handlers(ast, appRoute, pagesApi)) {
        // Only handlers that know who the caller is; no auth at all is SW-A01's finding.
        const authed = (h.wrapperName && AUTH_WRAPPER_RE.test(h.wrapperName)) || evidence.inFunction(h.fn);
        if (!authed) continue;
        const body = src(h.fn);
        // A comparison of the fetched record's owner anywhere in the handler counts.
        if (/(!==?|===?)/.test(body) && OWNER_COL_RE.test(body) && IDENTITY_RE.test(body)) continue;

        for (const q of lookups(h.fn, src, isTainted, project, file, text)) {
          const label = serverActions ? `Server action ${h.name}` : `${h.method ?? "Handler"} ${url ?? file}`;
          out.push({
            file,
            ...project.position(file, q.at.start ?? 0),
            confidence: q.confidence,
            title: `${label} ${q.verb} ${q.table ? `a record from ${q.table}` : "a record"} by ID without checking the owner`,
            why:
              `This handler checks that someone is signed in, then ${q.verb} the record whose ID comes from the request ` +
              `(\`${short(src(q.at))}\`) without checking it belongs to them. ${q.why} Any signed-in user can change the ID ` +
              `and reach other users' records.`,
            fix: q.fix,
            fixPrompt:
              `In ${file}, the ${serverActions ? `server action ${h.name}` : `${h.method ?? ""} handler`.trim()} ${q.verb} a record by an ID ` +
              `from the request without checking the signed-in user owns it. Add an ownership condition to the query ` +
              `(for example the record's user_id must equal the signed-in user's id), return 404 if nothing matches, ` +
              `and apply the same check to every other handler in this file that takes an ID.`,
          });
        }
      }
    }
    return out;
  },
};

interface Lookup {
  /** The request-derived ID expression. */
  at: Node;
  table: string | null;
  verb: string;
  confidence: Confidence;
  why: string;
  fix: string;
}

function lookups(
  fn: Node,
  src: (n: Node) => string,
  isTainted: (n: Node) => boolean,
  project: ProjectFiles,
  file: string,
  text: string,
): Lookup[] {
  const out: Lookup[] = [];
  const inner = new Set<Node>();
  const calls: Node[] = [];
  walkAst(fn, (n) => {
    if (n.type !== "CallExpression") return;
    calls.push(n);
    if (n.callee.type === "MemberExpression" && n.callee.object.type === "CallExpression") inner.add(n.callee.object);
  });
  const owned = (e: Node) => OWNER_COL_RE.test(src(e)) || IDENTITY_RE.test(src(e));

  for (const top of calls.filter((c) => !inner.has(c))) {
    const chain = flatten(top);
    if (!chain) continue;

    // Supabase: client.from("t")…eq("id", input) with no owner filter, on a client that skips RLS.
    const from = chain.calls.find((c) => c.name === "from");
    if (from) {
      const idFilter = chain.calls.find(
        (c) => (c.name === "eq" || c.name === "match") && c.args.length > 0 && filterPicksId(c, isTainted),
      );
      if (!idFilter) continue;
      const ownerFilter = chain.calls.some((c) => c !== idFilter && /^(eq|match|filter|in|or)$/.test(c.name) && c.args.some(owned));
      if (ownerFilter || !bypassesRls(chain.root, src, project, file, text)) continue;
      const table = from.args[0]?.type === "StringLiteral" ? from.args[0].value : null;
      const verb = chain.calls.some((c) => c.name === "delete") ? "deletes" : chain.calls.some((c) => c.name === "update" || c.name === "upsert") ? "changes" : "reads";
      out.push({
        at: idValue(idFilter) ?? idFilter.node,
        table,
        verb,
        confidence: "high",
        why: "The query uses a Supabase client that bypasses row-level security, so nothing else stops it.",
        fix: `Add the owner to the filter, such as \`.eq("user_id", user.id)\`, so the query only matches the caller's own row. Better still, use the normal Supabase client with the user's session so row-level security applies.`,
      });
      continue;
    }

    // Prisma: prisma.note.findUnique({ where: { id: input } }) with no owner key in where.
    const last = chain.calls.at(-1)!;
    if (PRISMA_ONE.test(last.name) && chain.calls.length === 1 && last.args[0]?.type === "ObjectExpression") {
      const where = prop(last.args[0], "where");
      if (!where || where.type !== "ObjectExpression") continue;
      const idProp = where.properties.find(
        (p) => p.type === "ObjectProperty" && ID_COL_RE.test(keyName(p.key as Node) ?? "") && !OWNER_COL_RE.test(keyName(p.key as Node) ?? "") && isTainted(p.value as Node),
      );
      if (!idProp || idProp.type !== "ObjectProperty") continue;
      if (where.properties.some((p) => p !== idProp && p.type === "ObjectProperty" && (OWNER_COL_RE.test(keyName(p.key as Node) ?? "") || owned(p.value as Node)))) continue;
      const model = top.type === "CallExpression" && top.callee.type === "MemberExpression" && top.callee.object.type === "MemberExpression" &&
        top.callee.object.property.type === "Identifier" ? top.callee.object.property.name : null;
      out.push({
        at: idProp.value as Node,
        table: model,
        verb: /delete/.test(last.name) ? "deletes" : /update|upsert/.test(last.name) ? "changes" : "reads",
        confidence: "high",
        why: "Prisma talks to the database directly, so no row-level security applies.",
        fix: `Add the owner to the where clause, such as \`where: { id, userId: user.id }\` with \`findFirst\` (or a compound unique key), and return 404 when nothing matches.`,
      });
      continue;
    }

    // Drizzle: db.select().from(t).where(eq(t.id, input)) with no owner condition.
    const where = chain.calls.find((c) => c.name === "where");
    if (where && where.args[0]?.type === "CallExpression") {
      const cond = where.args[0];
      const condName = cond.callee.type === "Identifier" ? cond.callee.name : "";
      if (condName === "eq" && cond.arguments[1] && isTainted(cond.arguments[1] as Node) && /\.(id|\w+Id)$/.test(src(cond.arguments[0] as Node))) {
        out.push({
          at: cond.arguments[1] as Node,
          table: null,
          verb: chain.calls.some((c) => c.name === "delete") ? "deletes" : chain.calls.some((c) => c.name === "update") ? "changes" : "reads",
          confidence: "medium",
          why: "Drizzle queries the database directly, so no row-level security applies.",
          fix: `Combine the ID with the owner: \`.where(and(eq(t.id, id), eq(t.userId, user.id)))\`, and return 404 when nothing matches.`,
        });
      }
    }
  }
  return out;
}

interface ChainCall {
  name: string;
  args: Node[];
  node: Node;
}

/** a.b(…).c(…).d(…) as [b, c, d] with root `a`. */
function flatten(top: Node): { root: Node; calls: ChainCall[] } | null {
  const calls: ChainCall[] = [];
  let n: Node = top;
  while (n.type === "CallExpression" && n.callee.type === "MemberExpression" && n.callee.property.type === "Identifier") {
    calls.unshift({ name: n.callee.property.name, args: n.arguments as Node[], node: n });
    n = n.callee.object as Node;
  }
  // prisma.note.findUnique: step past plain member accesses to the root.
  while (n.type === "MemberExpression") n = n.object as Node;
  return calls.length ? { root: n, calls } : null;
}

function filterPicksId(c: ChainCall, isTainted: (n: Node) => boolean): boolean {
  if (c.name === "eq") {
    const col = c.args[0]?.type === "StringLiteral" ? c.args[0].value : "";
    return ID_COL_RE.test(col) && !OWNER_COL_RE.test(col) && !!c.args[1] && isTainted(c.args[1]);
  }
  const obj = c.args[0];
  return obj?.type === "ObjectExpression" && obj.properties.some(
    (p) => p.type === "ObjectProperty" && ID_COL_RE.test(keyName(p.key as Node) ?? "") && isTainted(p.value as Node),
  );
}

function idValue(c: ChainCall): Node | null {
  if (c.name === "eq") return c.args[1] ?? null;
  const obj = c.args[0];
  if (obj?.type !== "ObjectExpression") return null;
  const p = obj.properties.find((x) => x.type === "ObjectProperty" && ID_COL_RE.test(keyName(x.key as Node) ?? ""));
  return p && p.type === "ObjectProperty" ? (p.value as Node) : null;
}

/** Whether a Supabase client skips row-level security: named as admin, or built with the service-role key. */
function bypassesRls(root: Node, src: (n: Node) => string, project: ProjectFiles, file: string, text: string): boolean {
  const SERVICE = /SERVICE_ROLE|service_role|sb_secret_|SUPABASE_SECRET/;
  if (root.type === "CallExpression") return SERVICE.test(src(root));
  if (root.type !== "Identifier") return false;
  if (/admin|service/i.test(root.name)) return true;
  // Imported from a local module that builds it with the service-role key?
  const imp = new RegExp(`import\\s*\\{[^}]*\\b${root.name}\\b[^}]*\\}\\s*from\\s*["']([^"']+)["']`).exec(text);
  if (imp) {
    const target = resolveImport(project, file, imp[1]!);
    return !!target && SERVICE.test(project.read(target) ?? "");
  }
  // Built in this file?
  const local = new RegExp(`\\b${root.name}\\s*=\\s*createClient\\(([\\s\\S]{0,300}?)\\)`).exec(text);
  return !!local && SERVICE.test(local[1]!);
}

function prop(obj: Node, name: string): Node | null {
  if (obj.type !== "ObjectExpression") return null;
  const p = obj.properties.find((x) => x.type === "ObjectProperty" && keyName(x.key as Node) === name);
  return p && p.type === "ObjectProperty" ? (p.value as Node) : null;
}

function keyName(k: Node): string | null {
  return k.type === "Identifier" ? k.name : k.type === "StringLiteral" ? k.value : null;
}

function short(s: string): string {
  const one = s.replace(/\s+/g, " ");
  return one.length > 40 ? `${one.slice(0, 37)}...` : one;
}
